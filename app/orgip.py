"""Szervezet / ASN / domain → a céghez tartozó IP-tartományok felderítése nyilvános forrásokból.

AI nélkül, kizárólag olvasó HTTP GET lekérdezésekből:
  - RIPE DB REST (rest.db.ripe.net): org-keresés névre → ORG-handle; inverz inetnum/inet6num/aut-num.
  - RIPEstat (stat.ripe.net): ASN → BGP-ben meghirdetett prefixek (GLOBÁLIS, bármely RIR), AS-holder.
  - ARIN REST (whois.arin.net/rest): org-keresés + hálózatok (ARIN-régió) – best-effort.
  - PeeringDB (peeringdb.com/api): org → hálózatok/ASN-ek (globális, peering-cégek) – best-effort.
  - domain-seed: a megadott domain feloldása → IP → ASN (RIPEstat network-info).

Minden forrás hibatűrő és időkorlátos; ha egy forrás hibázik, csendben kimarad. A WHOIS elavulhat, ezért a
találatok netname/descr/ország mezővel jönnek, hogy a felhasználó visszaigazolhassa. Nem kihasználás.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import re

import httpx

UA = "sadrobot org-ip discovery"
_TIMEOUT = 25
_MAX_PREFIXES = 2000          # védelmi felső korlát a visszaadott prefixekre

# Netname-alapú pool-osztályozás (jelleg). KONFIGURÁLHATÓ: a RECON_POOL_PATTERNS env egy JSON-lista
# ([["minta","kind"], ...], ahol kind = dynamic|fixed); ezek a beépített minták ELÉ kerülnek, így
# felülírhatók más operátorok konvenciói. A netname-ben keresünk (kis/nagybetű nem számít).
# FONTOS: a jelleg operátor által karbantartott registry-jelzés, NEM bizonyít mobilt/lakosságit/CGNAT-ot.
_DEFAULT_POOL_PATTERNS = [
    (r"dynamic|dynpool|-dyn-|-dsl-|-pool|pppoe|-mobile|-mob-|-cgn|cgnat|residential|-res-|customer", "dynamic"),
    (r"-fixed|-static|-stat-|-biz|business|-corp|-leased|-dedicated|-srv|-hosting", "fixed"),
]


def _pool_patterns() -> list[tuple[re.Pattern, str]]:
    pats: list[tuple[str, str]] = []
    raw = os.getenv("RECON_POOL_PATTERNS", "")
    if raw:
        try:
            for item in json.loads(raw):
                if isinstance(item, (list, tuple)) and len(item) == 2:
                    pats.append((str(item[0]), str(item[1])))
        except Exception:  # noqa: BLE001
            pass
    pats += _DEFAULT_POOL_PATTERNS
    return [(re.compile(p, re.I), k) for p, k in pats]


_POOL_RE = _pool_patterns()


def _classify(netname: str, status: str) -> str:
    """Prefix-rekord jellege a RIPE netname + status alapján. Csak jelzés, nem bizonyíték.
    dynamic/fixed a netname-mintából; allocation/aggregate/assigned a RIPE státuszból; különben unknown."""
    nn = netname or ""
    for rx, kind in _POOL_RE:
        if rx.search(nn):
            return kind
    s = (status or "").upper()
    if s.startswith("ALLOCATED"):
        return "allocation"
    if "AGGREGATED" in s:
        return "aggregate"
    if s.startswith("ASSIGNED"):
        return "assigned"
    return "unknown"


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(headers={"User-Agent": UA, "Accept": "application/json"},
                            follow_redirects=True, timeout=_TIMEOUT)


def _range_to_cidrs(start: str, end: str) -> list[str]:
    try:
        nets = ipaddress.summarize_address_range(ipaddress.ip_address(start), ipaddress.ip_address(end))
        return [str(n) for n in nets]
    except Exception:  # noqa: BLE001
        return []


def _attrs(obj: dict) -> dict:
    """RIPE REST objektum attribútumai dict-ként (az ismétlődőket az utolsó nyeri – nekünk elég)."""
    out = {}
    for a in obj.get("attributes", {}).get("attribute", []):
        out.setdefault(a["name"], a["value"])
    return out


# ------------------------------------------------ RIPE ------------------------------------------------
async def ripe_orgs(client: httpx.AsyncClient, name: str) -> list[dict]:
    url = ("https://rest.db.ripe.net/search?query-string=" + httpx.QueryParams({"q": name})["q"]
           + "&type-filter=organisation&flags=no-referenced&source=RIPE")
    try:
        r = await client.get(url)
        objs = r.json().get("objects", {}).get("object", [])
    except Exception:  # noqa: BLE001
        return []
    out = []
    for o in objs:
        a = _attrs(o)
        if a.get("organisation"):
            out.append({"handle": a["organisation"], "name": a.get("org-name", ""), "source": "RIPE"})
    return out


async def ripe_resources(client: httpx.AsyncClient, handle: str) -> dict:
    """ORG-handle → RIPE inetnum/inet6num (CIDR-ekké bontva) + aut-num (ASN-ek)."""
    url = ("https://rest.db.ripe.net/search?query-string=" + handle
           + "&inverse-attribute=org&type-filter=inetnum&type-filter=inet6num&type-filter=aut-num"
           + "&flags=no-referenced&source=RIPE")
    try:
        r = await client.get(url)
        objs = r.json().get("objects", {}).get("object", [])
    except Exception:  # noqa: BLE001
        return {"prefixes": [], "asns": []}
    prefixes, asns = [], []
    for o in objs:
        a = _attrs(o)
        t = o.get("type")
        if t == "inetnum" and a.get("inetnum"):
            start, _, end = a["inetnum"].partition(" - ")
            for cidr in _range_to_cidrs(start.strip(), end.strip()):
                prefixes.append({"prefix": cidr, "source": "RIPE whois",
                                 "netname": a.get("netname", ""), "cc": a.get("country", ""),
                                 "descr": a.get("descr", ""), "status": a.get("status", "")})
        elif t == "inet6num" and a.get("inet6num"):
            prefixes.append({"prefix": a["inet6num"], "source": "RIPE whois",
                             "netname": a.get("netname", ""), "cc": a.get("country", ""),
                             "descr": a.get("descr", ""), "status": a.get("status", "")})
        elif t == "aut-num" and a.get("aut-num"):
            asns.append({"asn": a["aut-num"], "name": a.get("as-name", ""), "source": "RIPE"})
    return {"prefixes": prefixes, "asns": asns}


# ---------------------------------------------- RIPEstat ----------------------------------------------
async def announced_prefixes(client: httpx.AsyncClient, asn: str) -> list[dict]:
    """ASN → BGP-ben ténylegesen meghirdetett prefixek (globális, bármely RIR)."""
    num = re.sub(r"(?i)^as", "", str(asn)).strip()
    if not num.isdigit():
        return []
    try:
        r = await client.get(f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{num}")
        ps = r.json().get("data", {}).get("prefixes", [])
    except Exception:  # noqa: BLE001
        return []
    return [{"prefix": p["prefix"], "source": f"BGP AS{num}", "netname": "", "cc": "", "descr": ""}
            for p in ps if p.get("prefix")]


async def asn_holder(client: httpx.AsyncClient, asn: str) -> str:
    num = re.sub(r"(?i)^as", "", str(asn)).strip()
    try:
        r = await client.get(f"https://stat.ripe.net/data/as-overview/data.json?resource=AS{num}")
        return r.json().get("data", {}).get("holder", "") or ""
    except Exception:  # noqa: BLE001
        return ""


async def asn_org(client: httpx.AsyncClient, asn: str) -> str | None:
    """ASN → a birtokló RIPE org-handle (az aut-num `org:` mezője). Így egy BGP-ből felbukkant ASN-ből
    (pl. domain-seed → infra-cég ASN-je) kibontható a cég teljes RIPE-inetnum-listája."""
    num = re.sub(r"(?i)^as", "", str(asn)).strip()
    if not num.isdigit():
        return None
    try:
        r = await client.get(f"https://rest.db.ripe.net/ripe/aut-num/AS{num}.json")
        for o in r.json().get("objects", {}).get("object", []):
            org = _attrs(o).get("org")
            if org:
                return org
    except Exception:  # noqa: BLE001
        pass
    return None


# ------------------------------------------------ ARIN ------------------------------------------------
async def arin_orgs(client: httpx.AsyncClient, name: str) -> list[dict]:
    try:
        r = await client.get(f"https://whois.arin.net/rest/orgs;name={httpx.QueryParams({'q': name})['q']}")
        data = r.json()
    except Exception:  # noqa: BLE001
        return []
    refs = data.get("orgs", {}).get("orgRef", [])
    refs = refs if isinstance(refs, list) else [refs]
    return [{"handle": o.get("@handle", ""), "name": o.get("@name", ""), "source": "ARIN"}
            for o in refs if o.get("@handle")]


async def arin_nets(client: httpx.AsyncClient, handle: str) -> list[dict]:
    try:
        r = await client.get(f"https://whois.arin.net/rest/org/{handle}/nets")
        data = r.json()
    except Exception:  # noqa: BLE001
        return []
    refs = data.get("nets", {}).get("netRef", [])
    refs = refs if isinstance(refs, list) else [refs]
    out = []
    for n in refs:
        start, end = n.get("@startAddress"), n.get("@endAddress")
        if start and end:
            for cidr in _range_to_cidrs(start, end):
                out.append({"prefix": cidr, "source": "ARIN whois",
                            "netname": n.get("@name", ""), "cc": "", "descr": n.get("$", "")})
    return out


# ---------------------------------------------- PeeringDB ----------------------------------------------
async def peeringdb_asns(client: httpx.AsyncClient, name: str) -> list[dict]:
    try:
        r = await client.get(f"https://www.peeringdb.com/api/net?name__contains={httpx.QueryParams({'q': name})['q']}")
        nets = r.json().get("data", [])
    except Exception:  # noqa: BLE001
        return []
    return [{"asn": f"AS{n['asn']}", "name": n.get("name", ""), "source": "PeeringDB"}
            for n in nets if n.get("asn")]


# --------------------------------------------- domain-seed ---------------------------------------------
async def domain_seed_asns(client: httpx.AsyncClient, domain: str) -> list[dict]:
    """A megadott domain feloldása → IP → ASN (RIPEstat network-info, önálló – nincs külső függőség).
    A cég infrastruktúra-ASN-jének kiindulópontja (pl. yettel.hu → AS8448/CETIN)."""
    import socket
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(domain, None, type=socket.SOCK_STREAM)
        ips = list({i[4][0] for i in infos})
    except Exception:  # noqa: BLE001
        return []
    out, seen = [], set()
    for ip in ips[:4]:
        try:
            r = await client.get(f"https://stat.ripe.net/data/network-info/data.json?resource={ip}")
            data = r.json().get("data", {})
        except Exception:  # noqa: BLE001
            continue
        for asn in (data.get("asns") or []):
            if asn not in seen:
                seen.add(asn)
                out.append({"asn": f"AS{asn}", "name": "", "source": "domain→ASN"})
    return out


def _looks_asn(q: str) -> str | None:
    m = re.fullmatch(r"(?i)as?(\d{1,10})", q.strip())
    return m.group(1) if m else None


def _looks_domain(q: str) -> bool:
    return bool(re.fullmatch(r"(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(\.(?!-)[A-Za-z0-9-]{1,63})+", q.strip()))


async def discover(query: str, rirs: list[str] | None = None) -> dict:
    """Egységes belépő. A `query` TÖBB seedet is tartalmazhat (vesszővel/pontosvesszővel/sortöréssel),
    és minden seed lehet ASN, domain vagy cégnév – a legteljesebb lefedettséghez érdemes a cégnevet ÉS a
    fő domaint (és ismert ASN-t) együtt megadni, mert az infrastruktúra gyakran külön cég/ASN alatt van
    (pl. Yettel → CETIN / AS8448). Visszaad: {query, orgs, asns, prefixes, notes}, forrás-jelöléssel."""
    q = (query or "").strip()
    rirs = rirs or ["ripe", "arin", "peeringdb"]
    seeds = [s.strip() for s in re.split(r"[,;\n]+", q) if s.strip()][:10] or [q]
    orgs: list[dict] = []
    asns: dict[str, dict] = {}        # asn -> {asn, name, source}
    prefixes: list[dict] = []
    notes: list[str] = []
    done_handles: set[str] = set()

    def add_asn(a: dict):
        key = re.sub(r"(?i)^as", "AS", a["asn"])
        asns.setdefault(key, {"asn": key, "name": a.get("name", ""), "source": a.get("source", "")})

    async def pull_ripe_handle(h: str, src_label: str):
        if not h or h in done_handles:
            return
        done_handles.add(h)
        orgs.append({"handle": h, "name": "", "source": src_label})
        res = await ripe_resources(client, h)
        prefixes.extend(res["prefixes"])
        for a in res["asns"]:
            add_asn(a)

    async with _client() as client:
        # 1) seedenként: ASN / domain / cégnév
        for s in seeds:
            asn_num = _looks_asn(s)
            if asn_num:
                add_asn({"asn": f"AS{asn_num}", "name": await asn_holder(client, asn_num), "source": "megadott ASN"})
            elif _looks_domain(s):
                for a in await domain_seed_asns(client, s):
                    add_asn(a)
            else:
                tasks = []
                if "ripe" in rirs:
                    tasks.append(("ripe_org", ripe_orgs(client, s)))
                if "arin" in rirs:
                    tasks.append(("arin_org", arin_orgs(client, s)))
                if "peeringdb" in rirs:
                    tasks.append(("pdb", peeringdb_asns(client, s)))
                for (kind, _), res in zip(tasks, await asyncio.gather(*(t[1] for t in tasks), return_exceptions=True)):
                    if isinstance(res, Exception):
                        continue
                    if kind in ("ripe_org", "arin_org"):
                        orgs += res
                    elif kind == "pdb":
                        for a in res:
                            add_asn(a)
        if any(_looks_domain(s) for s in seeds):
            notes.append("Domain-seed: a feloldott IP-k ASN-je – lehet ISP/CDN/infra-cég is, ellenőrizd a holder nevét.")

        # 2) RIPE org-handle-ök erőforrásai (a cégnév-keresésből)
        for h in [o["handle"] for o in list(orgs) if o["source"] == "RIPE"][:6]:
            await pull_ripe_handle(h, "RIPE")
        # 3) ARIN org-handle-ök hálózatai
        arin_handles = [o["handle"] for o in orgs if o["source"] == "ARIN"][:6]
        for res in await asyncio.gather(*(arin_nets(client, h) for h in arin_handles), return_exceptions=True):
            if not isinstance(res, Exception):
                prefixes += res
        # 4) ASN → birtokló RIPE org → annak inetnumai (a domain-seed/BGP ASN-ekből, pl. AS8448→CETIN)
        for a in list(asns):
            org = await asn_org(client, a)
            if org:
                await pull_ripe_handle(org, "RIPE (ASN→org)")
        # 5) minden összegyűjtött ASN → BGP-prefixek (globális, a no-org tartományokat is lefedi)
        for res in await asyncio.gather(*(announced_prefixes(client, a) for a in list(asns)), return_exceptions=True):
            if not isinstance(res, Exception):
                prefixes += res
        # 6) ASN holder-nevek kitöltése
        for a in asns.values():
            if not a.get("name"):
                a["name"] = await asn_holder(client, a["asn"])

    # a legjobb netname/status/ország összegyűjtése prefixenként: a BGP-sor üres, a RIPE-sor nem – egyesítjük,
    # hogy a BGP-ben meghirdetett /16–/18 is megkapja a RIPE-címkéjét (jelleg-osztályozáshoz)
    merged: dict[str, dict] = {}
    for p in prefixes:
        e = merged.setdefault(p["prefix"], {})
        for f in ("netname", "cc", "descr", "status"):
            if not e.get(f) and p.get(f):
                e[f] = p[f]

    # dedup prefix (az első forrást megtartva), netname/status-szal gazdagítva + jelleg (kind)
    seen, uniq = set(), []
    for p in prefixes:
        if p["prefix"] in seen:
            continue
        seen.add(p["prefix"])
        e = merged.get(p["prefix"], {})
        for f in ("netname", "cc", "descr", "status"):
            if not p.get(f) and e.get(f):
                p[f] = e[f]
        p.setdefault("status", "")
        p["kind"] = _classify(p.get("netname", ""), p.get("status", ""))
        uniq.append(p)
        if len(uniq) >= _MAX_PREFIXES:
            notes.append(f"{len(prefixes)} prefix → az első {_MAX_PREFIXES} megtartva.")
            break
    uniq.sort(key=lambda p: (":" in p["prefix"], p["prefix"]))
    return {"query": q, "orgs": orgs, "asns": list(asns.values()), "prefixes": uniq, "notes": notes}
