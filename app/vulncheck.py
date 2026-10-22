"""Kitett szolgáltatások / nyilvánvaló félrekonfigurációk kíméletes jelzése.

Védelmi (defenzív) felderítés, engedélyezett célponton. MINDEN ellenőrzés:
  - csak olvasás, kizárólag GET, átirányítást nem követ,
  - egy kérés / ellenőrzés, rövid időtúllépés, méretkorlát,
  - nem kihasználás: csak a nyilvánvaló kitettséget ismeri fel, nem támad.

A kérések a hostnévvel mennek (Host-fejléc + TLS SNI), kivéve a közvetlen
IP:port szolgáltatásokat (Elasticsearch/Prometheus/Grafana/Kibana), ahol az IP a cél.

Minden egyes ellenőrzés try/except-ben fut, a függvény soha nem dob kifelé.
"""
from __future__ import annotations

import asyncio  # noqa: F401  (a motor async kontextusban hívja)

# Web-portok → séma. Ha egyik sincs nyitva, a web-ellenőrzéseket kihagyjuk.
_HTTP_PORTS = (80, 8080, 8000, 8008, 8081, 8088)
_HTTPS_PORTS = (443, 8443)
_MAX = 65536          # legfeljebb ennyi bájtot olvasunk
_EV = 160             # evidence-hossz korlát


def _trunc(s: str, n: int = _EV) -> str:
    """Evidence rövidítése egy sorba, n karakterre."""
    s = " ".join((s or "").split())
    return s[:n]


def _xf(id_, sev, title_hu, title_en, ev_hu, ev_en):
    """Kétnyelvű kitettség-finding (a riport a nyelvhez illő mezőt mutatja)."""
    return {"id": id_, "severity": sev, "title": title_hu, "title_en": title_en,
            "evidence": _trunc(ev_hu), "evidence_en": _trunc(ev_en)}


async def _get(client, url: str, host: str | None = None, timeout: float = 6.0):
    """Biztonságos GET: (status, text) vagy None. Átirányítást nem követ, max ~64 KB-ot olvas.

    A `host` megadásakor a Host-fejlécet felülírjuk (vhost / SNI a séma+host URL-nél úgyis adott).
    """
    try:
        headers = {"Host": host} if host else None
        r = await client.get(url, headers=headers, timeout=timeout)
        raw = r.content[:_MAX] if r.content else b""
        text = raw.decode("utf-8", "replace")
        return r.status_code, text
    except Exception:  # noqa: BLE001  – hálózati/TLS/egyéb hiba: némán kihagyjuk
        return None


def _web_scheme_for(open_ports: list[int]) -> tuple[str, int] | None:
    """A legelső elérhető web-port+séma (https-t előnyben). -> (scheme, port) vagy None."""
    for p in _HTTPS_PORTS:
        if p in open_ports:
            return "https", p
    for p in _HTTP_PORTS:
        if p in open_ports:
            return "http", p
    return None


async def exposed_checks(client, host: str, ip: str, open_ports: list[int],
                         timeout: float = 6.0) -> list[dict]:
    """Kitett szolgáltatások / félrekonfigurációk kíméletes felismerése.

    client     : httpx.AsyncClient (follow_redirects=False, verify=False)
    host       : hostnév (Host-fejléc + TLS SNI)
    ip         : feloldott IP (közvetlen IP:port szolgáltatásokhoz)
    open_ports : a már megtalált nyitott TCP-portok
    -> findingök listája: {id, severity, title, evidence}. Üres lista, ha nincs semmi.
    """
    findings: list[dict] = []
    ports = set(open_ports or [])

    # ------------------------------ web-ellenőrzések ------------------------------
    web = _web_scheme_for(open_ports or [])
    if web:
        scheme, port = web
        base = f"{scheme}://{host}" if port in (80, 443) else f"{scheme}://{host}:{port}"

        # 1) Kitett .git könyvtár
        try:
            res = await _get(client, f"{base}/.git/HEAD", timeout=timeout)
            if res and res[0] == 200 and res[1].lstrip().startswith("ref:"):
                findings.append(_xf("exposed-git", "high",
                    "Kitett .git könyvtár", "Exposed .git directory",
                    f"GET /.git/HEAD → {res[1]}", f"GET /.git/HEAD → {res[1]}"))
        except Exception:  # noqa: BLE001
            pass

        # 2) Kitett .env fájl
        try:
            res = await _get(client, f"{base}/.env", timeout=timeout)
            if res and res[0] == 200:
                body = res[1]
                for needle in ("APP_KEY=", "DB_PASSWORD", "SECRET"):
                    if needle in body:
                        findings.append(_xf("exposed-dotenv", "critical",
                            "Kitett .env fájl", "Exposed .env file",
                            f"GET /.env tartalmaz: {needle}", f"GET /.env contains: {needle}"))
                        break
        except Exception:  # noqa: BLE001
            pass

        # 3) Directory listing (gyökér, majd /uploads/)
        try:
            for path in ("/", "/uploads/"):
                res = await _get(client, f"{base}{path}", timeout=timeout)
                if res and res[0] == 200 and "Index of /" in res[1]:
                    findings.append(_xf("dir-listing", "medium",
                        "Nyitott könyvtárlistázás", "Open directory listing",
                        f"GET {path} → 'Index of /'", f"GET {path} → 'Index of /'"))
                    break
        except Exception:  # noqa: BLE001
            pass

        # 4) Apache server-status
        try:
            res = await _get(client, f"{base}/server-status", timeout=timeout)
            if res and res[0] == 200 and "Apache Server Status" in res[1]:
                findings.append(_xf("apache-server-status", "low",
                    "Kitett Apache server-status", "Exposed Apache server-status",
                    "GET /server-status → 'Apache Server Status'",
                    "GET /server-status → 'Apache Server Status'"))
        except Exception:  # noqa: BLE001
            pass

        # 5) Spring Boot actuator
        try:
            for path in ("/actuator", "/actuator/health"):
                res = await _get(client, f"{base}{path}", timeout=timeout)
                if res and res[0] == 200:
                    body = res[1]
                    low = body.lower()
                    if ('"status"' in low) or ('"_links"' in low) or ("actuator" in low):
                        findings.append(_xf("spring-actuator", "medium",
                            "Kitett Spring actuator", "Exposed Spring actuator",
                            f"GET {path} → {body}", f"GET {path} → {body}"))
                        break
        except Exception:  # noqa: BLE001
            pass

        # 6) phpinfo információszivárgás
        try:
            res = await _get(client, f"{base}/phpinfo.php", timeout=timeout)
            if res and res[0] == 200 and "PHP Version" in res[1]:
                findings.append(_xf("phpinfo", "low",
                    "Kitett phpinfo (információszivárgás)", "Exposed phpinfo (information disclosure)",
                    "GET /phpinfo.php → 'PHP Version'", "GET /phpinfo.php → 'PHP Version'"))
        except Exception:  # noqa: BLE001
            pass

    # --------------------- közvetlen IP:port szolgáltatások ----------------------
    # Elasticsearch (9200)
    if 9200 in ports:
        try:
            res = await _get(client, f"http://{ip}:9200/", timeout=timeout)
            if res and res[0] == 200 and "cluster_name" in res[1]:
                ev_hu = "GET :9200/ cluster_name jelen van"
                ev_en = "GET :9200/ cluster_name present"
                try:
                    idx = await _get(client, f"http://{ip}:9200/_cat/indices", timeout=timeout)
                    if idx and idx[0] == 200 and idx[1].strip():
                        ev_hu = ev_en = f"_cat/indices: {idx[1]}"
                except Exception:  # noqa: BLE001
                    pass
                findings.append(_xf("open-elasticsearch", "high",
                    "Nyílt Elasticsearch (auth nélkül)", "Open Elasticsearch (no auth)", ev_hu, ev_en))
        except Exception:  # noqa: BLE001
            pass

    # Prometheus (9090)
    if 9090 in ports:
        try:
            for path in ("/-/healthy", "/"):
                res = await _get(client, f"http://{ip}:9090{path}", timeout=timeout)
                if res and res[0] == 200 and "Prometheus" in res[1]:
                    findings.append(_xf("open-prometheus", "low",
                        "Kitett Prometheus", "Exposed Prometheus",
                        f"GET :9090{path} → 'Prometheus'", f"GET :9090{path} → 'Prometheus'"))
                    break
        except Exception:  # noqa: BLE001
            pass

    # Grafana (3000)
    if 3000 in ports:
        try:
            res = await _get(client, f"http://{ip}:3000/login", timeout=timeout)
            if res and res[0] == 200 and "Grafana" in res[1]:
                findings.append(_xf("exposed-grafana", "info",
                    "Elérhető Grafana bejelentkezés", "Reachable Grafana login",
                    "GET :3000/login → 'Grafana'", "GET :3000/login → 'Grafana'"))
        except Exception:  # noqa: BLE001
            pass

    # Kibana (5601)
    if 5601 in ports:
        try:
            res = await _get(client, f"http://{ip}:5601/", timeout=timeout)
            if res and res[0] == 200 and "kibana" in res[1].lower():
                findings.append(_xf("exposed-kibana", "low",
                    "Elérhető Kibana", "Reachable Kibana",
                    "GET :5601/ → 'kibana'", "GET :5601/ → 'kibana'"))
        except Exception:  # noqa: BLE001
            pass

    return findings


# ---------------- Verzió-alapú ismert-CVE jelzés (nem kihasználás) ----------------
import re as _re  # noqa: E402

# PHP „php2shell" – kritikus, hitelesítés nélküli RCE a PHP-motorban (alap konfig érintett).
# Javított kiadások ághoz kötve; az ág alatt minden korábbi patch sebezhető.
_PHP2SHELL_FIXED = {(8, 5): (8, 5, 12), (8, 4): (8, 4, 27), (8, 3): (8, 3, 36), (8, 2): (8, 2, 35)}
_PHP2SHELL = {"id": "php2shell", "cve": "CVE-2026-109618 / CVE-2026-109619",
              "severity": "critical", "fixed": "8.5.12 / 8.4.27 / 8.3.36 / 8.2.35"}


def _parse_ver(s):
    m = _re.search(r"PHP/(\d+)\.(\d+)\.(\d+)", s or "")
    return tuple(int(x) for x in m.groups()) if m else None


def _php2shell_vulnerable(ver):
    """ver=(maj,min,patch). True ha a php2shell (CVE-2026-109618/109619) érinti."""
    branch = ver[:2]
    if branch in _PHP2SHELL_FIXED:
        return ver < _PHP2SHELL_FIXED[branch]       # ágon belül a javított patch alatt
    return ver < (8, 2)                              # 8.1 és régebbi (EOL) – backport nélkül sebezhető


def php_cve_findings(powered_by: str = "", server: str = "") -> list[dict]:
    """Detektált PHP-verzió (X-Powered-By / Server fejléc) → ismert kritikus CVE jelzés.
    Verzió-alapú, NEM kihasználás: a verzióegyezés nem bizonyít kihasználhatóságot."""
    ver = _parse_ver(powered_by) or _parse_ver(server)
    if not ver or not _php2shell_vulnerable(ver):
        return []
    vs = ".".join(map(str, ver))
    return [{"id": _PHP2SHELL["id"], "severity": _PHP2SHELL["severity"],
             "title": f"PHP php2shell RCE ({_PHP2SHELL['cve']})",
             "evidence": f"PHP {vs} — javítva: {_PHP2SHELL['fixed']} (verzió alapján, alap konfig érintett)"}]
