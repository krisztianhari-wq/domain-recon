"""A feltérképezés motorja: egy domainből hostok, élő/nem élő, portok, szolgáltatások.

Fokozatok (stage):
  enumerate → CT-naplóból (certspotter) aldomének + opcionális prefix-szótár + az apex.
  resolve   → DNS-feloldás (A/AAAA/CNAME); NXDOMAIN kiesik; IP-k rögzítése.
  scan      → nyitott portok IP-nként egyszer (kíméletes, korlátozott párhuzamossággal).
  (ujjlenyomat a scan közben: web-portnál HTTP cím + TLS SAN, egyébként banner.)

Intenzitás: polite | normal | aggressive – ez szabja a párhuzamosságot és az időtúllépést.
Csak olyan célpontot vizsgálj, amelyhez van engedélyed.
"""
from __future__ import annotations

import asyncio
import ipaddress
import socket
import time

import httpx

from . import fingerprint as fp
from . import netchecks as nc
from .ports import EXPECTED_WEB, resolve_profile, svc

CT_URL = "https://api.certspotter.com/v1/issuances?domain={d}&include_subdomains=true&expand=dns_names"
UA = "domain-recon/1.0 (+sadrobot; availability/exposure mapping)"

# Kis, gyakori prefix-szótár az opcionális brute-felderítéshez (kíméletes, DNS-only).
COMMON_PREFIXES = [
    "www", "mail", "smtp", "imap", "pop", "webmail", "ns1", "ns2", "dns", "mx",
    "api", "api2", "app", "apps", "admin", "portal", "dev", "test", "staging",
    "stage", "uat", "qa", "demo", "beta", "cdn", "static", "assets", "img",
    "media", "files", "download", "vpn", "remote", "gw", "gateway", "proxy",
    "git", "gitlab", "jenkins", "ci", "jira", "wiki", "docs", "blog", "shop",
    "store", "login", "auth", "sso", "id", "account", "my", "secure", "status",
    "monitor", "grafana", "kibana", "prometheus", "db", "sql", "mysql", "redis",
    "ftp", "sftp", "backup", "old", "new", "intranet", "extranet", "cloud",
    "m", "mobile", "wap", "ads", "ad", "crm", "erp", "hr", "support", "help",
]

INTENSITY = {
    # név:        (port-párhuzam/ IP, host-párhuzam, port-timeout, fingerprint-timeout, host-késleltetés)
    "polite":     (12, 2, 3.0, 6.0, 0.4),
    "normal":     (64, 4, 2.0, 5.0, 0.1),
    "aggressive": (250, 8, 1.2, 4.0, 0.0),
}

_RUNNING: dict[str, asyncio.Task] = {}


def is_public(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_global and not a.is_multicast


class Cancelled(Exception):
    pass


class Engine:
    def __init__(self, db, scan_id: str, domain: str, opts: dict):
        self.db = db
        self.id = scan_id
        self.domain = domain.strip().lower().rstrip(".")
        self.opts = opts
        self.profile, self.profile_name = resolve_profile(opts.get("ports", "service"), opts.get("custom_ports", ""))
        inten = opts.get("intensity", "polite")
        self.pc, self.hc, self.ptimeout, self.ftimeout, self.hdelay = INTENSITY.get(inten, INTENSITY["polite"])
        self.allow_private = bool(opts.get("allow_private"))
        self.use_ct = opts.get("ct", True)
        self.use_wordlist = bool(opts.get("wordlist"))
        self.do_ports = opts.get("scan_ports", True)
        self._ip_ports: dict[str, list[int]] = {}   # IP → nyitott portok (cache, egy IP-t egyszer szkennelünk)
        self._canceled = False
        self._n_cand = 0

    def _check(self):
        if self._canceled:
            raise Cancelled()

    # ---------------- 1) felsorolás ----------------
    async def enumerate(self, client: httpx.AsyncClient) -> set[str]:
        self.db.set_progress(self.id, "enumerate", 0, 0)
        hosts: set[str] = {self.domain}
        if self.use_ct:
            hosts |= await self._ct_hosts(client)
        if self.use_wordlist:
            hosts |= {f"{p}.{self.domain}" for p in COMMON_PREFIXES}
        return {h for h in hosts if h.endswith(self.domain)}

    async def _ct_hosts(self, client: httpx.AsyncClient, pages: int = 8) -> set[str]:
        hosts: set[str] = set()
        after = None
        for _ in range(pages):
            self._check()
            url = CT_URL.format(d=self.domain) + (f"&after={after}" if after else "")
            try:
                r = await client.get(url, timeout=40)
                if r.status_code != 200:
                    break
                data = r.json()
            except Exception:  # noqa: BLE001
                break
            if not data:
                break
            for rec in data:
                for n in rec.get("dns_names", []):
                    n = n.lower().lstrip("*.")
                    if n.endswith(self.domain):
                        hosts.add(n)
            after = data[-1].get("id")
            await asyncio.sleep(1)
        return hosts

    # ---------------- 2) feloldás ----------------
    async def resolve_all(self, hosts: list[str]) -> dict[str, dict]:
        out: dict[str, dict] = {}
        total = len(hosts)
        sem = asyncio.Semaphore(32)
        done = 0

        async def one(h: str):
            nonlocal done
            async with sem:
                info = await self._resolve(h)
            done += 1
            if done % 5 == 0 or done == total:
                self.db.set_progress(self.id, "resolve", done, total)
            if info:
                out[h] = info
                rec = {"source": "ct/seed", **info, "ports": [], "alive": bool(info["ips"]), "scanned": False}
                self.db.upsert_host(self.id, h, rec)

        self.db.set_progress(self.id, "resolve", 0, total)
        await asyncio.gather(*(one(h) for h in hosts))
        return out

    async def _resolve(self, host: str) -> dict | None:
        self._check()
        ips: list[str] = []
        try:
            infos = await asyncio.get_running_loop().getaddrinfo(host, None, type=socket.SOCK_STREAM)
            for info in infos:
                ip = info[4][0]
                if ip not in ips:
                    ips.append(ip)
        except (socket.gaierror, OSError):
            pass
        cname = None
        _, cn = await nc.dns_query(host, "CNAME")
        if cn:
            cname = cn[0]
        if not ips:
            return None
        pub = [ip for ip in ips if is_public(ip)]
        return {"ips": ips, "public_ips": pub, "cname": cname,
                "v4": [i for i in ips if ":" not in i], "v6": [i for i in ips if ":" in i]}

    # ---------------- 3) portscan + ujjlenyomat ----------------
    async def scan_hosts(self, resolved: dict[str, dict]):
        targets = [(h, i) for h, i in resolved.items()
                   if (i["public_ips"] or (self.allow_private and i["ips"]))]
        total = len(targets)
        self.db.set_progress(self.id, "scan", 0, total)
        sem = asyncio.Semaphore(self.hc)
        done = 0
        port_total = 0
        live = len([1 for _h, i in resolved.items() if i["ips"]])

        async def one(host: str, info: dict):
            nonlocal done, port_total
            async with sem:
                self._check()
                scan_ips = info["public_ips"] if not self.allow_private else info["ips"]
                ports_out = await self._scan_host(host, scan_ips)
                rec = {"source": "ct/seed", **info, "ports": ports_out,
                       "alive": bool(info["ips"]), "scanned": True}
                # TLS SAN-ból előkerült új nevek jelzése (kiegészítő felderítés)
                sans = sorted({s.lower().lstrip("*.") for p in ports_out
                               for s in (p.get("tls", {}) or {}).get("sans", [])
                               if s.lower().lstrip("*.").endswith(self.domain)})
                if sans:
                    rec["tls_sans"] = sans
                self.db.upsert_host(self.id, host, rec)
                port_total += len(ports_out)
                if self.hdelay:
                    await asyncio.sleep(self.hdelay)
            done += 1
            self.db.set_progress(self.id, "scan", done, total)
            self.db.set_counts(self.id, self._n_cand, live, port_total)

        await asyncio.gather(*(one(h, i) for h, i in targets))

    async def _scan_host(self, host: str, ips: list[str]) -> list[dict]:
        if not self.do_ports or not ips:
            return []
        ip = ips[0]                                   # kíméletes: hostonként egy IP-t szkennelünk
        if ip in self._ip_ports:
            open_ports = self._ip_ports[ip]
        else:
            open_ports = await self._scan_ip(ip)
            self._ip_ports[ip] = open_ports
        out: list[dict] = []
        # a hoston belül korlátozott párhuzamosság: kíméletes, de nem vár sorban minden időtúllépésre
        fsem = asyncio.Semaphore(min(self.pc, 6))

        async def one(p: int):
            async with fsem:
                self._check()
                info = await fp.fingerprint(host, ip, p, timeout=self.ftimeout)
                info["name"] = svc(p)
                info["expected"] = p in EXPECTED_WEB
                out.append(info)

        await asyncio.gather(*(one(p) for p in open_ports))
        out.sort(key=lambda x: x["port"])
        return out

    async def _scan_ip(self, ip: str) -> list[int]:
        sem = asyncio.Semaphore(self.pc)
        found: list[int] = []

        async def probe(port: int):
            async with sem:
                self._check()
                ok, _ = await nc.tcp_check(ip, port, self.ptimeout)
                if ok:
                    found.append(port)

        await asyncio.gather(*(probe(p) for p in self.profile))
        return sorted(found)

    # ---------------- vezénylés ----------------
    async def run(self):
        self.db.set_status(self.id, "running")
        try:
            async with httpx.AsyncClient(headers={"User-Agent": UA}, follow_redirects=False) as client:
                cand = sorted(await self.enumerate(client))
                self._n_cand = len(cand)
                self.db.set_counts(self.id, len(cand), 0, 0)
                resolved = await self.resolve_all(cand)
                live = len(resolved)
                self.db.set_counts(self.id, len(cand), live, 0)
                if self.do_ports:
                    await self.scan_hosts(resolved)
                n_ports = sum(len(h.get("ports", [])) for h in self.db.hosts(self.id))
                self.db.set_counts(self.id, len(cand), live, n_ports)
            self.db.set_progress(self.id, "done", 1, 1)
            self.db.set_status(self.id, "done")
        except Cancelled:
            self.db.set_status(self.id, "canceled", error="A felhasználó megszakította.")
        except Exception as e:  # noqa: BLE001
            self.db.set_status(self.id, "error", error=f"{e.__class__.__name__}: {e}"[:300])
        finally:
            _RUNNING.pop(self.id, None)

    def cancel(self):
        self._canceled = True


def start_scan(db, scan_id: str, domain: str, opts: dict) -> Engine:
    eng = Engine(db, scan_id, domain, opts)
    task = asyncio.create_task(eng.run())
    eng._task = task  # type: ignore[attr-defined]
    _RUNNING[scan_id] = task
    # megszakításhoz az Engine-t is elérhetővé tesszük
    _ENGINES[scan_id] = eng
    return eng


_ENGINES: dict[str, Engine] = {}


def cancel_scan(scan_id: str) -> bool:
    eng = _ENGINES.get(scan_id)
    if eng:
        eng.cancel()
        return True
    return False
