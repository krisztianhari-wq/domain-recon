"""Passzív aldomén-források (kulcs nélküli, nyilvános). Mind a célpont MEGÉRINTÉSE nélkül dolgozik:
tanúsítvány-naplók, passzív DNS-aggregátorok és webarchívum nevekből gyűjt.

Minden forrás hibatűrő (egy forrás kiesése nem állítja meg a többit), és saját időkorláttal fut.
"""
from __future__ import annotations

import asyncio
import re

import httpx

_HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9\-]{0,62})(\.[a-z0-9]([a-z0-9\-]{0,62}))+$")


def _clean(name: str, domain: str) -> str | None:
    n = (name or "").strip().lower().lstrip("*.").rstrip(".")
    if not n or " " in n:
        return None
    if not (n == domain or n.endswith("." + domain)):
        return None
    if not _HOST_RE.match(n):
        return None
    return n


async def _certspotter(client, domain, out):
    after = None
    for _ in range(6):
        url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
        if after:
            url += f"&after={after}"
        r = await client.get(url, timeout=30)
        if r.status_code != 200:
            break
        data = r.json()
        if not data:
            break
        for rec in data:
            for n in rec.get("dns_names", []):
                c = _clean(n, domain)
                if c:
                    out.add(c)
        after = data[-1].get("id")
        await asyncio.sleep(0.5)


async def _crtsh(client, domain, out):
    r = await client.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=40)
    if r.status_code != 200:
        return
    for rec in r.json():
        for n in str(rec.get("name_value", "")).splitlines():
            c = _clean(n, domain)
            if c:
                out.add(c)


async def _hackertarget(client, domain, out, ip_hint):
    r = await client.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=30)
    if r.status_code != 200 or "API count exceeded" in r.text or "error" in r.text.lower():
        return
    for line in r.text.splitlines():
        host, _, ip = line.partition(",")
        c = _clean(host, domain)
        if c:
            out.add(c)
            if ip.strip():
                ip_hint.setdefault(c, set()).add(ip.strip())


async def _anubis(client, domain, out):
    r = await client.get(f"https://jldc.me/anubis/subdomains/{domain}", timeout=30)
    if r.status_code != 200:
        return
    for n in r.json():
        c = _clean(n, domain)
        if c:
            out.add(c)


async def _wayback(client, domain, out):
    url = (f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json"
           "&fl=original&collapse=urlkey&limit=20000")
    r = await client.get(url, timeout=40)
    if r.status_code != 200:
        return
    rows = r.json()
    for row in rows[1:] if rows and isinstance(rows[0], list) else []:
        m = re.search(r"https?://([^/:]+)", row[0])
        if m:
            c = _clean(m.group(1), domain)
            if c:
                out.add(c)


SOURCES = {
    "certspotter": _certspotter,
    "crt.sh": _crtsh,
    "anubis": _anubis,
    "wayback": _wayback,
}


async def gather(domain: str, client: httpx.AsyncClient, use_hackertarget: bool = True) -> tuple[set, dict]:
    """(hostok, ip_tippek). Minden forrást párhuzamosan futtat, hibatűrően."""
    out: set[str] = {domain}
    ip_hint: dict[str, set] = {}

    async def run(name, fn):
        try:
            if name == "hackertarget":
                await fn(client, domain, out, ip_hint)
            else:
                await fn(client, domain, out)
        except Exception:  # noqa: BLE001
            pass

    tasks = [run(n, f) for n, f in SOURCES.items()]
    if use_hackertarget:
        tasks.append(run("hackertarget", _hackertarget))
    await asyncio.gather(*tasks)
    return out, ip_hint
