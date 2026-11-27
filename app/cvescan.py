"""Ismert kritikus CVE-k felismerése a domain-recon CVE-fázisához – KÉT csoport, külön reportolva:

  method="version":     a `Server` / `X-Powered-By` fejlécből kiolvasott termék+verzió összevetése
                        ismert sebezhető tartományokkal (PHP, Apache httpd). Nem kihasználás.
  method="fingerprint": kíméletes, GET-only ujjlenyomat (pl. Confluence verzió a HTML-ből) →
                        ismert kritikus CVE. Szintén nem kihasználás; a verzióegyezés nem bizonyít
                        kihasználhatóságot.

A találatok KÉTNYELVŰEK: title/evidence (HU) + title_en/evidence_en (EN); a riport/UI a kiválasztott
nyelv szerinti mezőt mutatja. Minden ellenőrzés hibatűrő.
"""
from __future__ import annotations

import re


def _ver_tuple(s: str):
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", s or "")
    return tuple(int(x) for x in m.groups()) if m else None


def _f(id_, cve, sev, title_hu, title_en, ev_hu, ev_en, method):
    return {"id": id_, "cve": cve, "severity": sev, "method": method,
            "title": title_hu, "title_en": title_en, "evidence": ev_hu, "evidence_en": ev_en}


# ---------------- PHP ----------------
_PHP2SHELL_FIXED = {(8, 5): (8, 5, 12), (8, 4): (8, 4, 27), (8, 3): (8, 3, 36), (8, 2): (8, 2, 35)}
_PHP_4577_FIXED = {(8, 1): (8, 1, 29), (8, 2): (8, 2, 20), (8, 3): (8, 3, 8)}
_PHP2_FIX = "8.5.12 / 8.4.27 / 8.3.36 / 8.2.35"


def _php_version(server: str, powered_by: str):
    m = re.search(r"PHP/[\d.]+", (powered_by or "") + " " + (server or ""))
    return _ver_tuple(m.group(0)) if m else None


def _php_findings(ver, server: str) -> list[dict]:
    out = []
    vs = ".".join(map(str, ver))
    branch = ver[:2]
    fixed = _PHP2SHELL_FIXED.get(branch)
    if (fixed and ver < fixed) or (not fixed and ver < (8, 2)):
        out.append(_f("php2shell", "CVE-2026-109618 / CVE-2026-109619", "critical",
                      "PHP php2shell RCE", "PHP php2shell RCE",
                      f"PHP {vs} — javítva: {_PHP2_FIX} (alap konfig érintett)",
                      f"PHP {vs} — fixed: {_PHP2_FIX} (default config affected)", "version"))
    f4577 = _PHP_4577_FIXED.get(branch)
    win = bool(re.search(r"win(dows|32|64)|microsoft-iis", server or "", re.I))
    if f4577 and ver < f4577:
        sev = "critical" if win else "high"
        note_hu = "Windows+CGI megerősítve" if win else "csak Windows+CGI – ellenőrzendő"
        note_en = "Windows+CGI confirmed" if win else "Windows+CGI only – verify"
        out.append(_f("php-cgi-arginject", "CVE-2024-4577", sev,
                      "PHP-CGI argumentuminjekció (RCE)", "PHP-CGI argument injection (RCE)",
                      f"PHP {vs} — javítva: 8.1.29 / 8.2.20 / 8.3.8 ({note_hu})",
                      f"PHP {vs} — fixed: 8.1.29 / 8.2.20 / 8.3.8 ({note_en})", "version"))
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
        cve = "CVE-2021-42013" + (" / CVE-2021-41773" if ver == (2, 4, 49) else "")
        out.append(_f("apache-path-traversal", cve, "critical",
                      "Apache path traversal → RCE", "Apache path traversal → RCE",
                      f"Apache {vs} — javítva: 2.4.51", f"Apache {vs} — fixed: 2.4.51", "version"))
    if (2, 4, 0) <= ver <= (2, 4, 48):
        out.append(_f("apache-mod-proxy-ssrf", "CVE-2021-40438", "critical",
                      "Apache mod_proxy SSRF", "Apache mod_proxy SSRF",
                      f"Apache {vs} — javítva: 2.4.49 (mod_proxy esetén)",
                      f"Apache {vs} — fixed: 2.4.49 (mod_proxy only)", "version"))
    if (2, 4, 55) <= ver <= (2, 4, 70):
        out.append(_f("apache-http2-rce", "CVE-2026-119618", "high",
                      "Apache mod_http2 heap-RCE (ha HTTP/2 aktív)", "Apache mod_http2 heap RCE (if HTTP/2 enabled)",
                      f"Apache {vs} — javítva: 2.4.71 (csak ha mod_http2 + h2/h2c engedélyezett)",
                      f"Apache {vs} — fixed: 2.4.71 (only if mod_http2 + h2/h2c enabled)", "version"))
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
def _mmp(s: str):
    """major.minor.patch (patch alapból 0) – a 4. tagot (pl. build) figyelmen kívül hagyja."""
    m = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", s or "")
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)) if m else None


_CONF_VER = re.compile(r'ajs-version-number"\s+content="(\d+)\.(\d+)\.(\d+)', re.I)
_CONF_26134_FIXED = {(7, 4): (7, 4, 17), (7, 13): (7, 13, 7), (7, 14): (7, 14, 3), (7, 15): (7, 15, 2),
                     (7, 16): (7, 16, 4), (7, 17): (7, 17, 4), (7, 18): (7, 18, 1)}
_CONF_22515_FIXED = {(8, 0): (8, 5, 2), (8, 1): (8, 5, 2), (8, 2): (8, 5, 2),
                     (8, 3): (8, 3, 3), (8, 4): (8, 4, 3), (8, 5): (8, 5, 2)}


def _confluence(body: str, out: list):
    """Atlassian Confluence a root HTML-ből (ajs-version-number). Verzió-alapú ujjlenyomat, GET-only."""
    if "ajs-version-number" not in body and "Confluence" not in body:
        return
    m = _CONF_VER.search(body)
    if not m:
        out.append(_f("confluence", "—", "info", "Atlassian Confluence észlelve", "Atlassian Confluence detected",
                      "verzió nem olvasható ki – ellenőrizd a CVE-2022-26134 / CVE-2023-22515 / CVE-2026-90436 / CVE-2026-21589 ellen",
                      "version not readable – check against CVE-2022-26134 / CVE-2023-22515 / CVE-2026-90436 / CVE-2026-21589", "fingerprint"))
        return
    ver = tuple(int(x) for x in m.groups()); vs = ".".join(map(str, ver)); branch = ver[:2]
    f1 = _CONF_26134_FIXED.get(branch)
    if f1 and ver < f1:
        fx = ".".join(map(str, f1))
        out.append(_f("confluence-ognl", "CVE-2022-26134", "critical",
                      "Confluence OGNL-injekció (RCE)", "Confluence OGNL injection (RCE)",
                      f"Confluence {vs} — javítva: {fx}", f"Confluence {vs} — fixed: {fx}", "fingerprint"))
    f2 = _CONF_22515_FIXED.get(branch)
    if f2 and ver < f2:
        fx = ".".join(map(str, f2))
        out.append(_f("confluence-authbypass", "CVE-2023-22515", "critical",
                      "Confluence jogosultság-megkerülés", "Confluence broken access control",
                      f"Confluence {vs} — javítva: {fx}", f"Confluence {vs} — fixed: {fx}", "fingerprint"))
    # CVE-2026-90436 (Apache Axis / Remote API, aktívan kihasználva): 10.x nem érintett, javítva 9.2.28
    if ver < (9, 2, 28):
        out.append(_f("confluence-axis-rce", "CVE-2026-90436", "high",
                      "Confluence Axis/Remote API RCE (ha a Remote API aktív)",
                      "Confluence Axis/Remote API RCE (if Remote API enabled)",
                      f"Confluence {vs} — javítva: 9.2.28 (10.x nem érintett; csak ha a Remote API (XML-RPC/SOAP) be van kapcsolva)",
                      f"Confluence {vs} — fixed: 9.2.28 (10.x not affected; only if Remote API (XML-RPC/SOAP) enabled)", "fingerprint"))
    # CVE-2026-21589 – hitelesítés nélküli tetszőleges fájlolvasás (Atlassian advisory 2026-10-05, CISA KEV, aktívan kihasználva).
    # Javított Confluence DC: 9.2.26 (9.2 LTS) és 10.2.19 (10.2 LTS); minden korábbi érintett.
    cfix = "9.2.26" if ver < (9, 2, 26) else ("10.2.19" if (10, 0, 0) <= ver < (10, 2, 19) else None)
    if cfix:
        out.append(_f("confluence-file-read", "CVE-2026-21589", "high",
                      "Confluence tetszőleges fájlolvasás (hitelesítés nélkül)",
                      "Confluence unauthenticated arbitrary file read",
                      f"Confluence {vs} — javítva: {cfix} (aktívan kihasználva, CISA KEV)",
                      f"Confluence {vs} — fixed: {cfix} (actively exploited, CISA KEV)", "fingerprint"))
    # Java4Shell (CVE-2026-114938) – JVM-szintű, kívülről nem ellenőrizhető: csak emlékeztető a belső JDK-ellenőrzésre
    out.append(_f("java4shell-hint", "CVE-2026-114938", "info",
                  "Java-alapú (Confluence) – a bundled JDK-t belül ellenőrizd (Java4Shell)",
                  "Java-based (Confluence) – verify the bundled JDK internally (Java4Shell)",
                  "JDK-verzió kívülről nem látszik; javított: 17.0.21.1 / 21.0.13.1 / 25.0.5.1 / 27.0.1.1",
                  "JDK version not externally visible; fixed: 17.0.21.1 / 21.0.13.1 / 25.0.5.1 / 27.0.1.1", "fingerprint"))


# WordPress – a core verziója a generator metából vagy a wp-* assetek ?ver= paraméteréből (a core verziója).
_WP_GEN = re.compile(r'name=["\']generator["\']\s+content=["\']WordPress\s+(\d+\.\d+(?:\.\d+)?)', re.I)
_WP_ASSET = re.compile(r'/wp-(?:includes|admin|content)/[^"\']*?[?&]ver=(\d+\.\d+(?:\.\d+)?)', re.I)


def _wordpress(body: str, out: list):
    """WordPress core wp2shell (CVE-2026-63030 + CVE-2026-60137). Verzió a root HTML-ből, GET-only."""
    if "wp-content" not in body and "wp-includes" not in body and "WordPress" not in body:
        return
    m = _WP_GEN.search(body)
    ver = _mmp(m.group(1)) if m else None
    if not ver:
        m2 = _WP_ASSET.search(body)   # ha a generator el van rejtve, az asset ?ver= a core verziója
        ver = _mmp(m2.group(1)) if m2 else None
    if not ver:
        out.append(_f("wordpress", "—", "info", "WordPress észlelve", "WordPress detected",
                      "verzió nem olvasható ki – ellenőrizd a CVE-2026-63030 / CVE-2026-60137 (wp2shell) ellen",
                      "version not readable – check against CVE-2026-63030 / CVE-2026-60137 (wp2shell)", "fingerprint"))
        return
    vs = ".".join(map(str, ver))
    # Teljes, hitelesítés nélküli RCE-lánc (wp2shell): 6.9.0–6.9.4 → 6.9.5, 7.0.0–7.0.1 → 7.0.2. KEV, aktívan kihasználva.
    if (6, 9, 0) <= ver <= (6, 9, 4) or (7, 0, 0) <= ver <= (7, 0, 1):
        fx = "6.9.5" if ver[:2] == (6, 9) else "7.0.2"
        out.append(_f("wp2shell", "CVE-2026-63030 / CVE-2026-60137", "critical",
                      "WordPress wp2shell RCE (hitelesítés nélkül)", "WordPress wp2shell RCE (unauthenticated)",
                      f"WordPress {vs} — javítva: {fx} (aktívan kihasználva, CISA KEV)",
                      f"WordPress {vs} — fixed: {fx} (actively exploited, CISA KEV)", "fingerprint"))
    # A 6.8 ágat csak az SQLi-fél (CVE-2026-60137) érinti, a teljes lánc nem: 6.8.0–6.8.5 → 6.8.6.
    elif (6, 8, 0) <= ver <= (6, 8, 5):
        out.append(_f("wp-sqli-60137", "CVE-2026-60137", "high",
                      "WordPress SQL-injekció (WP_Query)", "WordPress SQL injection (WP_Query)",
                      f"WordPress {vs} — javítva: 6.8.6 (a teljes wp2shell-lánc a 6.8 ágat nem érinti)",
                      f"WordPress {vs} — fixed: 6.8.6 (the full wp2shell chain does not affect the 6.8 branch)", "fingerprint"))


def _sharepoint(headers, out: list):
    """Microsoft SharePoint on-prem CVE-2026-56164. Build a MicrosoftSharePointTeamServices fejlécből.
    A termékvonalat a build nagyságrendje adja: <10000 → 2016, 10000–13999 → 2019, ≥14000 → Subscription Edition."""
    try:
        val = headers.get("microsoftsharepointteamservices", "") or ""
    except Exception:  # noqa: BLE001
        return
    if not val:
        return
    m = re.search(r"(\d+)\.(\d+)\.(\d+)\.(\d+)", val)
    if not m or int(m.group(1)) != 16:
        out.append(_f("sharepoint", "—", "info", "Microsoft SharePoint észlelve", "Microsoft SharePoint detected",
                      f"MicrosoftSharePointTeamServices: {val} – ellenőrizd a build-et a CVE-2026-56164 ellen",
                      f"MicrosoftSharePointTeamServices: {val} – check the build against CVE-2026-56164", "fingerprint"))
        return
    build = int(m.group(4))
    if build < 10000:
        line, fixb = "SharePoint 2016", 5561
    elif build < 14000:
        line, fixb = "SharePoint 2019", 10417
    else:
        line, fixb = "SharePoint Subscription Edition", 19725
    if build < fixb:
        out.append(_f("sharepoint-missing-auth", "CVE-2026-56164", "high",
                      "SharePoint hitelesítés nélküli jogosultság-emelés",
                      "SharePoint missing-authentication privilege elevation",
                      f"{line} build 16.0.0.{build} — javítva: build {fixb} (aktívan kihasználva, CISA KEV)",
                      f"{line} build 16.0.0.{build} — fixed: build {fixb} (actively exploited, CISA KEV)", "fingerprint"))


async def _owncloud(client, base: str, out: list):
    """ownCloud core CVE-2023-49105 (WebDAV auth-bypass). Verzió a /status.php unauth JSON-ból.
    A Nextcloud külön termék (azonos /status.php szerkezet), ezért kizárjuk."""
    try:
        r = await client.get(base + "/status.php", timeout=8)
        if r.status_code != 200:
            return
        j = r.json()
    except Exception:  # noqa: BLE001
        return
    if not isinstance(j, dict) or "owncloud" not in str(j.get("productname") or "").lower():
        return
    ver = _mmp(str(j.get("versionstring") or j.get("version") or ""))
    if not ver:
        out.append(_f("owncloud", "—", "info", "ownCloud észlelve", "ownCloud detected",
                      "verzió nem olvasható – ellenőrizd a CVE-2023-49105 ellen",
                      "version unreadable – check against CVE-2023-49105", "fingerprint"))
        return
    vs = ".".join(map(str, ver))
    if (10, 6, 0) <= ver <= (10, 13, 0):
        out.append(_f("owncloud-webdav-bypass", "CVE-2023-49105", "high",
                      "ownCloud WebDAV hitelesítés-megkerülés", "ownCloud WebDAV auth bypass",
                      f"ownCloud {vs} — javítva: 10.13.1 (kihasználhatóság konfigfüggő: nincs beállított signing key)",
                      f"ownCloud {vs} — fixed: 10.13.1 (exploitability config-dependent: unset signing key)", "fingerprint"))


async def _jira(client, base: str, out: list):
    """Atlassian Jira (Software / Service Management) CVE-2026-21589. Verzió a /rest/api/2/serverInfo unauth JSON-ból.
    Javított DC: 9.12.40, 10.3.26, 11.3.12; minden korábbi érintett (Atlassian advisory 2026-10-05, CISA KEV)."""
    try:
        r = await client.get(base + "/rest/api/2/serverInfo", timeout=8)
        if r.status_code != 200:
            return
        j = r.json()
    except Exception:  # noqa: BLE001
        return
    if not isinstance(j, dict) or "version" not in j:
        return
    ver = _mmp(str(j.get("version") or ""))
    if not ver:
        return
    vs = ".".join(map(str, ver)); dt = str(j.get("deploymentType") or "")
    fix = "9.12.40" if ver < (9, 12, 40) else (
          "10.3.26" if (10, 0, 0) <= ver < (10, 3, 26) else (
          "11.3.12" if (11, 0, 0) <= ver < (11, 3, 12) else None))
    if fix:
        suf = f" · {dt}" if dt else ""
        out.append(_f("jira-file-read", "CVE-2026-21589", "high",
                      "Jira tetszőleges fájlolvasás (hitelesítés nélkül)",
                      "Jira unauthenticated arbitrary file read",
                      f"Jira {vs}{suf} — javítva: {fix} (aktívan kihasználva, CISA KEV)",
                      f"Jira {vs}{suf} — fixed: {fix} (actively exploited, CISA KEV)", "fingerprint"))


async def fingerprint_cves(client, host: str, ports: list[int] | None = None) -> list[dict]:
    """B) Ujjlenyomat-alapú ismert CVE-k (method=fingerprint). Kíméletes, GET-only.
    A root oldalt egyszer kérjük le (Confluence/WordPress onnan a HTML-ből, SharePoint a fejlécből),
    majd két célzott, hitelesítés nélküli verzió-végpontot próbálunk (ownCloud /status.php, Jira serverInfo)."""
    out: list[dict] = []
    body, headers, root_base = "", {}, None
    for scheme in ("https", "http"):
        base = f"{scheme}://{host}"
        try:
            r = await client.get(base + "/", timeout=8)
            body, headers, root_base = r.text[:120000], r.headers, base
            break
        except Exception:  # noqa: BLE001
            continue
    if root_base is None:
        return out
    for fn in (_confluence, _wordpress):     # root HTML-alapú
        try:
            fn(body, out)
        except Exception:  # noqa: BLE001
            pass
    try:
        _sharepoint(headers, out)            # root fejléc-alapú
    except Exception:  # noqa: BLE001
        pass
    for probe in (_owncloud, _jira):         # célzott, kíméletes verzió-végpontok
        try:
            await probe(client, root_base, out)
        except Exception:  # noqa: BLE001
            pass
    return out
