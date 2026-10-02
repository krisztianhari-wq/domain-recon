"""A feltérképezés motorja két fázisban.

PASSZÍV (alapból fut) – a célpontot közvetlenül nem érinti:
  enumerate → több nyilvános forrás (certspotter, crt.sh, anubis, wayback, hackertarget)
  wildcard  → wildcard-DNS felismerés
  resolve   → DNS A/AAAA/CNAME (élő/nem élő)
  enrich    → reverse DNS (PTR) + ASN/ország/szervezet (Team Cymru), IP-nként egyszer
  posture   → apex DNS: MX/NS/TXT/CAA/SPF/DMARC/DKIM
  takeover  → lógó CNAME ismert szolgáltatásra (DNS-alapú gyanú)

AKTÍV (külön indítva) – a célpontot megérinti:
  scan        → nyitott TCP-portok (service/common/full/custom, intenzitás)
  fingerprint → banner, HTTP státusz/Server/title, TLS CN/SAN, technológia
  takeover+   → a gyanús hostok HTTP-ujjlenyomatos megerősítése
  exposed     → kockázatos kitett szolgáltatások jelzése

Csak engedélyezett célpontot vizsgálj.
"""
from __future__ import annotations

import asyncio
import ipaddress
import os
import socket
import time

import httpx

from . import enrich
from . import fingerprint as fp
from . import netchecks as nc
from . import sources
from .ports import EXPECTED_WEB, resolve_profile, svc

UA = "domain-recon/0.2 (+sadrobot; attack-surface mapping)"

COMMON_PREFIXES = [
    "www", "mail", "smtp", "imap", "pop", "webmail", "ns1", "ns2", "dns", "mx", "mx1", "mx2",
    "api", "api2", "apigw", "app", "apps", "admin", "portal", "dev", "test", "testing", "staging",
    "stage", "uat", "qa", "sandbox", "demo", "beta", "cdn", "static", "assets", "img", "images",
    "media", "files", "download", "downloads", "vpn", "remote", "gw", "gateway", "proxy", "edge",
    "git", "gitlab", "github", "jenkins", "ci", "cd", "jira", "confluence", "wiki", "docs", "doc",
    "blog", "shop", "store", "login", "auth", "sso", "id", "identity", "account", "accounts", "my",
    "secure", "status", "monitor", "monitoring", "grafana", "kibana", "prometheus", "metrics",
    "db", "sql", "mysql", "postgres", "redis", "mongo", "ftp", "sftp", "backup", "backups", "old",
    "new", "intranet", "extranet", "cloud", "m", "mobile", "wap", "ads", "ad", "crm", "erp", "hr",
    "support", "help", "helpdesk", "ticket", "mail2", "owa", "exchange", "autodiscover", "lync",
    "vpn2", "ssl", "web", "web1", "web2", "ns", "ns3", "smtp2", "relay", "mta", "internal", "corp",
    "partner", "partners", "client", "clients", "customer", "api-dev", "api-test", "stg", "prod",
]

INTENSITY = {
    "polite":     (12, 2, 3.0, 6.0, 0.4),
    "normal":     (64, 4, 2.0, 5.0, 0.1),
    "aggressive": (250, 8, 1.2, 4.0, 0.0),
}

_ENGINES: dict[str, "Engine"] = {}


def is_public(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_global and not a.is_multicast


def scannable(ip: str, allow_private: bool) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if a.is_loopback or a.is_link_local or a.is_unspecified or a.is_reserved or a.is_multicast:
        return False
    if a.is_global:
        return True
    return allow_private


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
        self.do_ports = opts.get("scan_ports", True)
        self.brute = bool(opts.get("brute"))
        self.max_hosts = int(os.getenv("RECON_MAX_HOSTS", "750"))
        self._gsem = asyncio.Semaphore(int(os.getenv("RECON_MAX_SOCKETS", "512")))
        self._ip_ports: dict[str, list[int]] = {}
        self._canceled = False

    def _check(self):
        if self._canceled:
            raise Cancelled()

    def cancel(self):
        self._canceled = True

    # ============================ PASSZÍV ============================
    async def run_passive(self):
        self.db.set_status(self.id, "running", stage="enumerate", active_status="none")
        _ENGINES[self.id] = self
        try:
            async with httpx.AsyncClient(headers={"User-Agent": UA}, follow_redirects=True) as client:
                # 1) források + wildcard
                self.db.set_progress(self.id, "enumerate", 0, 0)
                (hosts, ip_hint), wildcard = await asyncio.gather(
                    sources.gather(self.domain, client),
                    enrich.detect_wildcard(self.domain))
                cand = sorted(h for h in hosts if h == self.domain or h.endswith("." + self.domain))
                if len(cand) > self.max_hosts:
                    self.db.set_note(self.id, f"{len(cand)} jelölt host → az első {self.max_hosts} feldolgozva (RECON_MAX_HOSTS).")
                    cand = cand[:self.max_hosts]
                self.db.set_wildcard(self.id, sorted(wildcard))
                self.db.set_counts(self.id, len(cand), 0, 0)

                # 2) feloldás
                resolved = await self._resolve_all(cand, wildcard)

                # 3) gazdagítás (IP-nként egyszer: PTR + ASN)
                await self._enrich(resolved)

                # 4) domain-posture (apex)
                self.db.set_progress(self.id, "posture", 0, 1)
                posture = await enrich.domain_posture(self.domain)
                self.db.set_posture(self.id, posture)

                # 5) takeover-gyanú (DNS-alapú)
                self._mark_takeover(resolved, wildcard)

                live = sum(1 for i in resolved.values() if i["ips"])
                self.db.set_counts(self.id, len(cand), live, 0)
            self.db.set_progress(self.id, "done", 1, 1)
            self.db.set_status(self.id, "done")
        except Cancelled:
            self.db.set_status(self.id, "canceled", error="A felhasználó megszakította.")
        except Exception as e:  # noqa: BLE001
            self.db.set_status(self.id, "error", error=f"{e.__class__.__name__}: {e}"[:300])
        finally:
            _ENGINES.pop(self.id, None)

    async def _resolve_all(self, hosts: list[str], wildcard: set) -> dict[str, dict]:
        out: dict[str, dict] = {}
        total = len(hosts)
        sem = asyncio.Semaphore(32)
        done = 0
        self.db.set_progress(self.id, "resolve", 0, total)

        async def one(h: str):
            nonlocal done
            async with sem:
                info = await self._resolve(h)
            done += 1
            if done % 5 == 0 or done == total:
                self.db.set_progress(self.id, "resolve", done, total)
            if info:
                is_wild = bool(info["ips"]) and set(info["ips"]).issubset(wildcard) and h != self.domain
                out[h] = info
                rec = {**info, "alive": bool(info["ips"]), "wildcard": is_wild,
                       "ports": [], "scanned": False}
                self.db.upsert_host(self.id, h, rec)

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
            cname = cn[0].rstrip(".")
        if not ips and not cname:
            return None
        return {"ips": ips, "public_ips": [i for i in ips if is_public(i)], "cname": cname,
                "v4": [i for i in ips if ":" not in i], "v6": [i for i in ips if ":" in i], "ips_info": []}

    async def _enrich(self, resolved: dict[str, dict]):
        uniq = sorted({ip for i in resolved.values() for ip in i["ips"] if is_public(ip)})
        total = len(uniq)
        self.db.set_progress(self.id, "enrich", 0, total)
        cache: dict[str, dict] = {}
        sem = asyncio.Semaphore(16)
        done = 0

        async def one(ip: str):
            nonlocal done
            async with sem:
                self._check()
                ptr, asn = await asyncio.gather(enrich.reverse_dns(ip), enrich.asn_lookup(ip))
            cache[ip] = {"ip": ip, "ptr": ptr, **(asn or {})}
            done += 1
            self.db.set_progress(self.id, "enrich", done, total)

        await asyncio.gather(*(one(ip) for ip in uniq))
        # visszaírás a hostokra
        for h, info in resolved.items():
            info["ips_info"] = [cache.get(ip, {"ip": ip}) for ip in info["ips"]]
            rec = {**info, "alive": bool(info["ips"]),
                   "wildcard": info.get("wildcard", False), "ports": [], "scanned": False}
            self.db.upsert_host(self.id, h, rec)

    def _mark_takeover(self, resolved: dict[str, dict], wildcard: set):
        for h, info in resolved.items():
            cand = enrich.takeover_candidate(info.get("cname"))
            if cand:
                svc_name, cn = cand
                # gyanús, ha nem old fel (lógó), vagy ismert ujjlenyomatú szolgáltatás
                dangling = not info["ips"]
                info["takeover"] = {"service": svc_name, "cname": cn, "dangling": dangling, "confirmed": None}
                rec = {k: v for k, v in info.items()}
                rec.update(alive=bool(info["ips"]), ports=info.get("ports", []), scanned=False)
                self.db.upsert_host(self.id, h, rec)

    # ============================ AKTÍV ============================
    async def run_active(self):
        self.db.set_status(self.id, "done", active_status="running")   # a passzív kész marad; az aktív külön állapot
        self.db.set_active_progress(self.id, "scan", 0, 0)
        _ENGINES[self.id] = self
        try:
            hosts = {h["host"]: h for h in self.db.hosts(self.id)}
            targets = [(h, d) for h, d in hosts.items()
                       if any(scannable(ip, self.allow_private) for ip in d.get("ips", []))]
            total = len(targets)
            self.db.set_active_progress(self.id, "scan", 0, total)
            sem = asyncio.Semaphore(self.hc)
            done = 0
            async with httpx.AsyncClient(headers={"User-Agent": UA}, follow_redirects=False, verify=False) as client:

                async def one(host: str, d: dict):
                    nonlocal done
                    async with sem:
                        self._check()
                        ips = [ip for ip in d.get("ips", []) if scannable(ip, self.allow_private)]
                        ports_out = await self._scan_host(host, ips) if self.do_ports else []
                        d["ports"] = ports_out
                        d["scanned"] = True
                        d["tech"] = sorted({t for p in ports_out for t in p.get("tech", [])})
                        d["exposed_flags"] = self._exposed_flags(ports_out)
                        await self._confirm_takeover(client, host, d)
                        sans = sorted({s.lower().lstrip("*.") for p in ports_out
                                       for s in (p.get("tls", {}) or {}).get("sans", [])
                                       if s.lower().lstrip("*.").endswith(self.domain)})
                        if sans:
                            d["tls_sans"] = sans
                        self.db.upsert_host(self.id, host, d)
                        if self.hdelay:
                            await asyncio.sleep(self.hdelay)
                    done += 1
                    self.db.set_active_progress(self.id, "scan", done, total)
                    self.db.set_counts(self.id, self.db.get_scan(self.id)["n_hosts"],
                                       self.db.get_scan(self.id)["n_live"],
                                       sum(len(x.get("ports", [])) for x in self.db.hosts(self.id)))

                await asyncio.gather(*(one(h, d) for h, d in targets))

                # opcionális DNS-brute (aktív: nagy volumen)
                if self.brute:
                    await self._brute(client)
            self.db.set_active_progress(self.id, "done", 1, 1)
            self.db.set_status(self.id, "done", active_status="done")
        except Cancelled:
            self.db.set_status(self.id, "done", active_status="canceled")
        except Exception as e:  # noqa: BLE001
            self.db.set_status(self.id, "done", active_status="error", error=f"{e.__class__.__name__}: {e}"[:300])
        finally:
            _ENGINES.pop(self.id, None)

    async def _scan_host(self, host: str, ips: list[str]) -> list[dict]:
        if not ips:
            return []
        ip = ips[0]
        if ip in self._ip_ports:
            open_ports = self._ip_ports[ip]
        else:
            open_ports = await self._scan_ip(ip)
            self._ip_ports[ip] = open_ports
        out: list[dict] = []
        fsem = asyncio.Semaphore(min(self.pc, 6))

        async def one(p: int):
            async with fsem, self._gsem:
                self._check()
                info = await fp.fingerprint(host, ip, p, timeout=self.ftimeout)
                info["name"] = svc(p)
                info["expected"] = p in EXPECTED_WEB
                info["tech"] = (info.get("http") or {}).get("tech", [])
                out.append(info)

        await asyncio.gather(*(one(p) for p in open_ports))
        out.sort(key=lambda x: x["port"])
        return out

    async def _scan_ip(self, ip: str) -> list[int]:
        sem = asyncio.Semaphore(self.pc)
        found: list[int] = []

        async def probe(port: int):
            async with sem, self._gsem:
                self._check()
                ok, _ = await nc.tcp_check(ip, port, self.ptimeout)
                if ok:
                    found.append(port)

        await asyncio.gather(*(probe(p) for p in self.profile))
        return sorted(found)

    def _exposed_flags(self, ports_out: list[dict]) -> list[str]:
        """Kockázatos kitett szolgáltatások egyszerű jelzése (a 80/443 várt)."""
        risky = {3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch",
                 11211: "Memcached", 3389: "RDP", 23: "Telnet", 445: "SMB", 5900: "VNC", 2375: "Docker API",
                 9300: "ES-transport", 5601: "Kibana", 15672: "RabbitMQ", 2379: "etcd", 1433: "MSSQL"}
        flags = []
        for p in ports_out:
            if p["port"] in risky:
                flags.append(f"{risky[p['port']]} ({p['port']}) kitett")
        return flags

    async def _confirm_takeover(self, client, host: str, d: dict):
        t = d.get("takeover")
        if not t or not t.get("service"):
            return
        fpat = enrich.takeover_fingerprint(t["service"])
        try:
            for scheme in ("https", "http"):
                r = await client.get(f"{scheme}://{host}/", timeout=8)
                body = r.text[:20000]
                if fpat and fpat.lower() in body.lower():
                    t["confirmed"] = True
                    d["takeover"] = t
                    return
        except Exception:  # noqa: BLE001
            pass
        if t.get("dangling"):
            t["confirmed"] = None  # lógó, de HTTP-vel nem erősítve
        d["takeover"] = t

    async def _brute(self, client):
        self.db.set_active_progress(self.id, "brute", 0, len(COMMON_PREFIXES))
        wildcard = set(self.db.get_scan(self.id).get("wildcard") or [])
        sem = asyncio.Semaphore(32)
        done = 0
        new_hosts: dict[str, dict] = {}

        async def one(pfx: str):
            nonlocal done
            h = f"{pfx}.{self.domain}"
            async with sem:
                self._check()
                info = await self._resolve(h)
            done += 1
            if done % 10 == 0:
                self.db.set_active_progress(self.id, "brute", done, len(COMMON_PREFIXES))
            if info and info["ips"] and not set(info["ips"]).issubset(wildcard):
                if h not in {x["host"] for x in self.db.hosts(self.id)}:
                    new_hosts[h] = {**info, "alive": True, "wildcard": False, "ports": [],
                                    "scanned": False, "source_brute": True}

        await asyncio.gather(*(one(p) for p in COMMON_PREFIXES))
        for h, rec in new_hosts.items():
            self.db.upsert_host(self.id, h, rec)


# ---- indítók ----
def start_passive(db, scan_id: str, domain: str, opts: dict) -> Engine:
    eng = Engine(db, scan_id, domain, opts)
    asyncio.create_task(eng.run_passive())
    return eng


def start_active(db, scan_id: str, opts: dict) -> Engine:
    s = db.get_scan(scan_id)
    merged = {**(s.get("opts") or {}), **opts}
    eng = Engine(db, scan_id, s["domain"], merged)
    asyncio.create_task(eng.run_active())
    return eng


def cancel_scan(scan_id: str) -> bool:
    eng = _ENGINES.get(scan_id)
    if eng:
        eng.cancel()
        return True
    return False
