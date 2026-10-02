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
                findings.append({
                    "id": "exposed-git",
                    "severity": "high",
                    "title": "Kitett .git könyvtár",
                    "evidence": _trunc(f"GET /.git/HEAD → {res[1]}"),
                })
        except Exception:  # noqa: BLE001
            pass

        # 2) Kitett .env fájl
        try:
            res = await _get(client, f"{base}/.env", timeout=timeout)
            if res and res[0] == 200:
                body = res[1]
                for needle in ("APP_KEY=", "DB_PASSWORD", "SECRET"):
                    if needle in body:
                        findings.append({
                            "id": "exposed-dotenv",
                            "severity": "critical",
                            "title": "Kitett .env fájl",
                            "evidence": _trunc(f"GET /.env tartalmaz: {needle}"),
                        })
                        break
        except Exception:  # noqa: BLE001
            pass

        # 3) Directory listing (gyökér, majd /uploads/)
        try:
            for path in ("/", "/uploads/"):
                res = await _get(client, f"{base}{path}", timeout=timeout)
                if res and res[0] == 200 and "Index of /" in res[1]:
                    findings.append({
                        "id": "dir-listing",
                        "severity": "medium",
                        "title": "Nyitott könyvtárlistázás",
                        "evidence": _trunc(f"GET {path} → 'Index of /'"),
                    })
                    break
        except Exception:  # noqa: BLE001
            pass

        # 4) Apache server-status
        try:
            res = await _get(client, f"{base}/server-status", timeout=timeout)
            if res and res[0] == 200 and "Apache Server Status" in res[1]:
                findings.append({
                    "id": "apache-server-status",
                    "severity": "low",
                    "title": "Kitett Apache server-status",
                    "evidence": _trunc("GET /server-status → 'Apache Server Status'"),
                })
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
                        findings.append({
                            "id": "spring-actuator",
                            "severity": "medium",
                            "title": "Kitett Spring actuator",
                            "evidence": _trunc(f"GET {path} → {body}"),
                        })
                        break
        except Exception:  # noqa: BLE001
            pass

        # 6) phpinfo információszivárgás
        try:
            res = await _get(client, f"{base}/phpinfo.php", timeout=timeout)
            if res and res[0] == 200 and "PHP Version" in res[1]:
                findings.append({
                    "id": "phpinfo",
                    "severity": "low",
                    "title": "Kitett phpinfo (információszivárgás)",
                    "evidence": _trunc("GET /phpinfo.php → 'PHP Version'"),
                })
        except Exception:  # noqa: BLE001
            pass

    # --------------------- közvetlen IP:port szolgáltatások ----------------------
    # Elasticsearch (9200)
    if 9200 in ports:
        try:
            res = await _get(client, f"http://{ip}:9200/", timeout=timeout)
            if res and res[0] == 200 and "cluster_name" in res[1]:
                evidence = f"GET :9200/ cluster_name jelen van"
                try:
                    idx = await _get(client, f"http://{ip}:9200/_cat/indices", timeout=timeout)
                    if idx and idx[0] == 200 and idx[1].strip():
                        evidence = f"_cat/indices: {idx[1]}"
                except Exception:  # noqa: BLE001
                    pass
                findings.append({
                    "id": "open-elasticsearch",
                    "severity": "high",
                    "title": "Nyílt Elasticsearch (auth nélkül)",
                    "evidence": _trunc(evidence),
                })
        except Exception:  # noqa: BLE001
            pass

    # Prometheus (9090)
    if 9090 in ports:
        try:
            for path in ("/-/healthy", "/"):
                res = await _get(client, f"http://{ip}:9090{path}", timeout=timeout)
                if res and res[0] == 200 and "Prometheus" in res[1]:
                    findings.append({
                        "id": "open-prometheus",
                        "severity": "low",
                        "title": "Kitett Prometheus",
                        "evidence": _trunc(f"GET :9090{path} → 'Prometheus'"),
                    })
                    break
        except Exception:  # noqa: BLE001
            pass

    # Grafana (3000)
    if 3000 in ports:
        try:
            res = await _get(client, f"http://{ip}:3000/login", timeout=timeout)
            if res and res[0] == 200 and "Grafana" in res[1]:
                findings.append({
                    "id": "exposed-grafana",
                    "severity": "info",
                    "title": "Elérhető Grafana bejelentkezés",
                    "evidence": _trunc("GET :3000/login → 'Grafana'"),
                })
        except Exception:  # noqa: BLE001
            pass

    # Kibana (5601)
    if 5601 in ports:
        try:
            res = await _get(client, f"http://{ip}:5601/", timeout=timeout)
            if res and res[0] == 200 and "kibana" in res[1].lower():
                findings.append({
                    "id": "exposed-kibana",
                    "severity": "low",
                    "title": "Elérhető Kibana",
                    "evidence": _trunc("GET :5601/ → 'kibana'"),
                })
        except Exception:  # noqa: BLE001
            pass

    return findings
