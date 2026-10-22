"""Ismert kritikus CVE-k felismerése a domain-recon CVE-fázisához – KÉT csoport, külön reportolva:

  method="version":     a `Server` / `X-Powered-By` fejlécből kiolvasott termék+verzió összevetése
                        ismert sebezhető tartományokkal (PHP, Apache httpd). Nem kihasználás.
  method="fingerprint": kíméletes, GET-only ujjlenyomat (pl. Confluence verzió a HTML-ből) →
                        ismert kritikus CVE. Szintén nem kihasználás; a verzióegyezés nem bizonyít
                        kihasználhatóságot (a jelzés ezt kiírja).

Minden ellenőrzés hibatűrő; a verzió-rész szinkron, az ujjlenyomat-rész async (egy GET / termék).
"""
from __future__ import annotations

import re

# ---------------- közös ----------------
def _ver_tuple(s: str):
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", s or "")
    return tuple(int(x) for x in m.groups()) if m else None


def _f(id_, cve, sev, title, evidence, method):
    return {"id": id_, "cve": cve, "severity": sev, "title": title, "evidence": evidence, "method": method}


# ---------------- PHP ----------------
_PHP2SHELL_FIXED = {(8, 5): (8, 5, 12), (8, 4): (8, 4, 27), (8, 3): (8, 3, 36), (8, 2): (8, 2, 35)}
_PHP_4577_FIXED = {(8, 1): (8, 1, 29), (8, 2): (8, 2, 20), (8, 3): (8, 3, 8)}


def _php_version(server: str, powered_by: str):
    return _ver_tuple(re.search(r"PHP/[\d.]+", (powered_by or "") + " " + (server or "")).group(0)) \
        if re.search(r"PHP/[\d.]+", (powered_by or "") + " " + (server or "")) else None


def _php_findings(ver, server: str) -> list[dict]:
    out = []
    vs = ".".join(map(str, ver))
    branch = ver[:2]
    # php2shell (CVE-2026-109618/109619) – motor, alap konfig
    fixed = _PHP2SHELL_FIXED.get(branch)
    if (fixed and ver < fixed) or (not fixed and ver < (8, 2)):
        out.append(_f("php2shell", "CVE-2026-109618 / CVE-2026-109619", "critical",
                      "PHP php2shell RCE", f"PHP {vs} — javítva: 8.5.12/8.4.27/8.3.36/8.2.35 (alap konfig érintett)", "version"))
    # CVE-2024-4577 – PHP-CGI argumentuminjekció (CSAK Windows + CGI/FastCGI)
    f4577 = _PHP_4577_FIXED.get(branch)
    win = bool(re.search(r"win(dows|32|64)|microsoft-iis", server or "", re.I))
    if f4577 and ver < f4577 and (win or branch in _PHP_4577_FIXED):
        sev = "critical" if win else "high"
        note = "Windows+CGI megerősítve" if win else "csak Windows+CGI érintett – ellenőrzendő"
        out.append(_f("php-cgi-arginject", "CVE-2024-4577", sev,
                      "PHP-CGI argumentuminjekció (RCE)", f"PHP {vs} — javítva: 8.1.29/8.2.20/8.3.8 ({note})", "version"))
    return out


# ---------------- Apache httpd ----------------
def _apache_findings(server: str) -> list[dict]:
    m = re.search(r"Apache/(\d+)\.(\d+)\.(\d+)", server or "")
    if not m:
        return []
    ver = tuple(int(x) for x in m.groups())
    vs = ".".join(map(str, ver))
    out = []
    if ver in ((2, 4, 49), (2, 4, 50)):
        out.append(_f("apache-path-traversal", "CVE-2021-42013" + (" / CVE-2021-41773" if ver == (2, 4, 49) else ""),
                      "critical", "Apache path traversal → RCE",
                      f"Apache {vs} — javítva: 2.4.51", "version"))
    if (2, 4, 0) <= ver <= (2, 4, 48):
        out.append(_f("apache-mod-proxy-ssrf", "CVE-2021-40438", "critical",
                      "Apache mod_proxy SSRF", f"Apache {vs} — javítva: 2.4.49 (mod_proxy esetén)", "version"))
    return out


def version_cves(server: str = "", powered_by: str = "") -> list[dict]:
    """A) Fejléc/verzió-alapú ismert CVE-k (method=version)."""
    out = []
    pv = _php_version(server, powered_by)
    if pv:
        out += _php_findings(pv, server)
    out += _apache_findings(server)
    return out


# ---------------- B) Ujjlenyomat-alapú (kíméletes GET) ----------------
_CONF_VER = re.compile(r'ajs-version-number"\s+content="(\d+)\.(\d+)\.(\d+)', re.I)
# Confluence: ág → első javított kiadás (CVE-2022-26134, OGNL RCE)
_CONF_26134_FIXED = {(7, 4): (7, 4, 17), (7, 13): (7, 13, 7), (7, 14): (7, 14, 3), (7, 15): (7, 15, 2),
                     (7, 16): (7, 16, 4), (7, 17): (7, 17, 4), (7, 18): (7, 18, 1)}
# CVE-2023-22515 (jogosultság-megkerülés): 8.0–8.5 ág, javítva 8.5.2 (és 8.3.3/8.4.3)
_CONF_22515_FIXED = {(8, 0): (8, 5, 2), (8, 1): (8, 5, 2), (8, 2): (8, 5, 2),
                     (8, 3): (8, 3, 3), (8, 4): (8, 4, 3), (8, 5): (8, 5, 2)}


async def _confluence(client, base: str, out: list):
    try:
        r = await client.get(base + "/", timeout=8)
        body = r.text[:120000]
    except Exception:  # noqa: BLE001
        return
    if "ajs-version-number" not in body and "Confluence" not in body:
        return
    m = _CONF_VER.search(body)
    if not m:
        out.append(_f("confluence", "—", "info", "Atlassian Confluence észlelve",
                      "verzió nem olvasható ki – ellenőrizd a CVE-2022-26134 / CVE-2023-22515 ellen", "fingerprint"))
        return
    ver = tuple(int(x) for x in m.groups()); vs = ".".join(map(str, ver)); branch = ver[:2]
    f1 = _CONF_26134_FIXED.get(branch)
    if f1 and ver < f1:
        out.append(_f("confluence-ognl", "CVE-2022-26134", "critical", "Confluence OGNL-injekció (RCE)",
                      f"Confluence {vs} — javítva: {'.'.join(map(str,f1))}", "fingerprint"))
    f2 = _CONF_22515_FIXED.get(branch)
    if f2 and ver < f2:
        out.append(_f("confluence-authbypass", "CVE-2023-22515", "critical",
                      "Confluence jogosultság-megkerülés", f"Confluence {vs} — javítva: {'.'.join(map(str,f2))}", "fingerprint"))


async def fingerprint_cves(client, host: str, ports: list[int] | None = None) -> list[dict]:
    """B) Ujjlenyomat-alapú ismert CVE-k (method=fingerprint). Kíméletes, GET-only."""
    out: list[dict] = []
    for scheme in ("https", "http"):
        base = f"{scheme}://{host}"
        try:
            await _confluence(client, base, out)
        except Exception:  # noqa: BLE001
            pass
        if out:
            break
    return out
