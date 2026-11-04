"""Kitett AI / low-code és monitoring eszközök kíméletes felismerése (GET-only, NEM kihasználás).

A CVE-fázishoz hasonló önálló fázis hívja (engine.run_svc). Minden host élő HTTP-jén
egyetlen alap-GET-tel azonosítjuk a terméket (cím/törzs), majd pár célzott GET-tel kiolvassuk
a verziót és az auth-állapotot. A jól ismert default-portokat (Ollama 11434, Netdata 19999,
Prometheus 9090, Portainer 9000) közvetlen IP:port-on is megnézzük, hogy a reverse proxy mögötti
és a közvetlenül kitett telepítéseket is elkapjuk.

Finding-formátum (a cve/vuln findingökkel megegyező, hogy a UI/riport újrahasznosítsa):
  {id, severity, title, title_en, evidence, evidence_en, product, version, cve?}
Súlyosság: elérhető eszköz → info/low; auth nélkül / nyitott regisztráció → high;
ismert sebezhető verzió (CVE) → a CVE súlyossága (high/critical).
"""
from __future__ import annotations

import re

_EV = 200  # evidence-hossz korlát


def _trunc(s: str, n: int = _EV) -> str:
    s = (s or "").strip().replace("\n", " ")
    return s if len(s) <= n else s[:n] + "…"


def _f(id_, sev, product, version, title_hu, title_en, ev_hu, ev_en, cve=""):
    return {"id": id_, "severity": sev, "product": product, "version": version or "",
            "cve": cve, "title": title_hu, "title_en": title_en,
            "evidence": _trunc(ev_hu), "evidence_en": _trunc(ev_en)}


async def _get(client, url: str, host: str | None = None, timeout: float = 6.0):
    """GET → (status, text[:40k], headers) vagy None. follow_redirects=False a hívó kliensen."""
    headers = {"Host": host} if host else None
    try:
        r = await client.get(url, timeout=timeout, headers=headers)
        return r.status_code, (r.text or "")[:40000], r.headers
    except Exception:  # noqa: BLE001
        return None


def _title(body: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", body or "", re.I | re.S)
    return (m.group(1).strip() if m else "")[:120]


def _ver(pat: str, text: str) -> str:
    m = re.search(pat, text or "")
    return m.group(1) if m else ""


def _vtuple(v: str):
    """'1.2.26' → (1,2,26); nem numerikus részeket kihagyja."""
    out = []
    for part in re.split(r"[.\-+]", (v or "").strip().lstrip("vV")):
        m = re.match(r"\d+", part)
        if not m:
            break
        out.append(int(m.group(0)))
    return tuple(out)


def _lt(v: str, target: tuple) -> bool:
    """Igaz, ha a v verzió kisebb a targetnél (ismeretlen verzió → False, nem jelölünk CVE-t)."""
    t = _vtuple(v)
    if not t:
        return False
    return t < target


# --------------------------------------------------------------------------------------
# Detektorok. Mindegyik egy élő HTTP-bázison (scheme://host) és/vagy közvetlen IP:port-on fut.
# A `base_probe(client, base, host)` és `port_probe(client, origin)` coroutine-ok egy finding-et
# vagy None-t adnak. A hívó dedupál termékre (első találat nyer).
# --------------------------------------------------------------------------------------

async def _ollama(client, origin, host=None):
    r = await _get(client, f"{origin}/api/version", host)
    root = await _get(client, f"{origin}/", host)
    is_ollama = (r and r[0] == 200 and '"version"' in r[1]) or (root and "Ollama is running" in (root[1] or ""))
    if not is_ollama:
        return None
    ver = _ver(r'"version"\s*:\s*"([^"]+)"', r[1]) if r else ""
    # Auth-állapot: a /api/tags auth nélkül listázza a modelleket → nyílt API
    tags = await _get(client, f"{origin}/api/tags", host)
    open_api = bool(tags and tags[0] == 200 and '"models"' in (tags[1] or ""))
    # CVE: < 0.1.34 → CVE-2024-37032 „Probllama" path-traversal RCE
    if _lt(ver, (0, 1, 34)):
        return _f("svc-ollama", "critical", "Ollama", ver,
                  "Ollama — sebezhető verzió (Probllama RCE)", "Ollama — vulnerable version (Probllama RCE)",
                  f"Ollama {ver} < 0.1.34 (CVE-2024-37032), /api/version alapján",
                  f"Ollama {ver} < 0.1.34 (CVE-2024-37032), via /api/version", cve="CVE-2024-37032")
    if open_api:
        return _f("svc-ollama", "high", "Ollama", ver,
                  "Nyílt Ollama API (auth nélkül)", "Open Ollama API (no auth)",
                  f"/api/tags auth nélkül listáz modelleket; Ollama {ver or '?'}",
                  f"/api/tags lists models without auth; Ollama {ver or '?'}")
    return _f("svc-ollama", "low", "Ollama", ver,
              "Elérhető Ollama", "Reachable Ollama",
              f"Ollama {ver or '?'} elérhető ({origin})", f"Ollama {ver or '?'} reachable ({origin})")


async def _openwebui(client, origin, host=None):
    r = await _get(client, f"{origin}/api/config", host)
    if not (r and r[0] == 200 and ('"version"' in r[1] or '"features"' in r[1]) and ("ollama" in r[1].lower() or "webui" in r[1].lower() or '"auth"' in r[1])):
        # Cím-alapú megerősítés, ha a config nem egyértelmű
        root = await _get(client, f"{origin}/", host)
        if not (root and "open webui" in _title(root[1]).lower()):
            return None
        body = ""
    else:
        body = r[1]
    ver = _ver(r'"version"\s*:\s*"([^"]+)"', body)
    signup_open = '"enable_signup":true' in body.replace(" ", "")
    auth_off = '"auth":false' in body.replace(" ", "")
    if signup_open or auth_off:
        why = "nyitott regisztráció" if signup_open else "auth kikapcsolva"
        why_en = "open signup" if signup_open else "auth disabled"
        return _f("svc-openwebui", "high", "Open WebUI", ver,
                  f"Open WebUI — {why}", f"Open WebUI — {why_en}",
                  f"/api/config: {why}; verzió {ver or '?'}", f"/api/config: {why_en}; version {ver or '?'}")
    return _f("svc-openwebui", "info", "Open WebUI", ver,
              "Elérhető Open WebUI", "Reachable Open WebUI",
              f"Open WebUI {ver or '?'} elérhető", f"Open WebUI {ver or '?'} reachable")


async def _flowise(client, origin, host=None):
    root = await _get(client, f"{origin}/", host)
    title = _title(root[1]) if root else ""
    if "flowise" not in title.lower():
        v = await _get(client, f"{origin}/api/v1/version", host)
        if not (v and v[0] == 200 and '"version"' in v[1]):
            return None
        ver = _ver(r'"version"\s*:\s*"([^"]+)"', v[1])
    else:
        v = await _get(client, f"{origin}/api/v1/version", host)
        ver = _ver(r'"version"\s*:\s*"([^"]+)"', v[1]) if v and v[0] == 200 else ""
    # Auth: a chatflow-lista auth nélkül 200 + JSON-tömb → nincs védelem
    cf = await _get(client, f"{origin}/api/v1/chatflows", host)
    no_auth = bool(cf and cf[0] == 200 and cf[1].lstrip().startswith("["))
    # CVE: < 1.6.5 → CVE-2024-31621 auth-bypass
    if _lt(ver, (1, 6, 5)):
        return _f("svc-flowise", "high", "Flowise", ver,
                  "Flowise — sebezhető verzió (auth-bypass)", "Flowise — vulnerable version (auth bypass)",
                  f"Flowise {ver} < 1.6.5 (CVE-2024-31621)", f"Flowise {ver} < 1.6.5 (CVE-2024-31621)",
                  cve="CVE-2024-31621")
    if no_auth:
        return _f("svc-flowise", "high", "Flowise", ver,
                  "Flowise — auth nélkül elérhető felület", "Flowise — UI reachable without auth",
                  f"/api/v1/chatflows auth nélkül 200; Flowise {ver or '?'}",
                  f"/api/v1/chatflows 200 without auth; Flowise {ver or '?'}")
    return _f("svc-flowise", "low", "Flowise", ver,
              "Elérhető Flowise", "Reachable Flowise",
              f"Flowise {ver or '?'} elérhető", f"Flowise {ver or '?'} reachable")


async def _langflow(client, origin, host=None):
    v = await _get(client, f"{origin}/api/v1/version", host)
    is_lf = v and v[0] == 200 and '"version"' in v[1] and ("langflow" in v[1].lower() or '"main_version"' in v[1])
    if not is_lf:
        h = await _get(client, f"{origin}/health", host)
        root = await _get(client, f"{origin}/", host)
        if not ((h and "ok" in (h[1] or "").lower() and root and "langflow" in _title(root[1]).lower())):
            return None
    ver = _ver(r'"version"\s*:\s*"([^"]+)"', v[1]) if v else ""
    # CVE: < 1.3.0 → CVE-2025-3248 unauth RCE (/api/v1/validate/code)
    if _lt(ver, (1, 3, 0)):
        return _f("svc-langflow", "critical", "Langflow", ver,
                  "Langflow — sebezhető verzió (unauth RCE)", "Langflow — vulnerable version (unauth RCE)",
                  f"Langflow {ver} < 1.3.0 (CVE-2025-3248)", f"Langflow {ver} < 1.3.0 (CVE-2025-3248)",
                  cve="CVE-2025-3248")
    return _f("svc-langflow", "low", "Langflow", ver,
              "Elérhető Langflow", "Reachable Langflow",
              f"Langflow {ver or '?'} elérhető", f"Langflow {ver or '?'} reachable")


async def _n8n(client, origin, host=None):
    s = await _get(client, f"{origin}/rest/settings", host)
    if not (s and s[0] == 200 and ("versionCli" in s[1] or "n8nMetadata" in s[1] or "endpointWebhook" in s[1])):
        root = await _get(client, f"{origin}/", host)
        if not (root and "n8n" in _title(root[1]).lower()):
            return None
        body = ""
    else:
        body = s[1]
    ver = _ver(r'"versionCli"\s*:\s*"([^"]+)"', body)
    # userManagement.showSetup == true → a kezdeti owner-fiók még nincs beállítva (nyitott)
    open_setup = '"showsetup":true' in body.replace(" ", "").lower()
    if open_setup:
        return _f("svc-n8n", "high", "n8n", ver,
                  "n8n — beállítatlan (nyitott owner-regisztráció)", "n8n — unconfigured (open owner signup)",
                  f"/rest/settings showSetup=true; n8n {ver or '?'}", f"/rest/settings showSetup=true; n8n {ver or '?'}")
    return _f("svc-n8n", "info", "n8n", ver,
              "Elérhető n8n", "Reachable n8n",
              f"n8n {ver or '?'} elérhető", f"n8n {ver or '?'} reachable")


async def _grafana(client, origin, host=None):
    r = await _get(client, f"{origin}/api/health", host)
    if not (r and r[0] == 200 and '"version"' in r[1] and ('"database"' in r[1] or '"commit"' in r[1])):
        return None
    ver = _ver(r'"version"\s*:\s*"([^"]+)"', r[1])
    # CVE: 8.0.0–8.3.0 → CVE-2021-43798 path-traversal (fájlolvasás)
    t = _vtuple(ver)
    if t and (8, 0, 0) <= t <= (8, 3, 0):
        return _f("svc-grafana", "high", "Grafana", ver,
                  "Grafana — sebezhető verzió (path traversal)", "Grafana — vulnerable version (path traversal)",
                  f"Grafana {ver} (8.0.0–8.3.0, CVE-2021-43798)", f"Grafana {ver} (8.0.0–8.3.0, CVE-2021-43798)",
                  cve="CVE-2021-43798")
    return _f("svc-grafana", "info", "Grafana", ver,
              "Elérhető Grafana", "Reachable Grafana",
              f"Grafana {ver or '?'} elérhető", f"Grafana {ver or '?'} reachable")


async def _cacti(client, origin, host=None):
    root = await _get(client, f"{origin}/", host)
    body = root[1] if root else ""
    hit = "cacti" in _title(body).lower() or "cacti.net" in body.lower() or "/cacti/" in body.lower()
    if not hit:
        alt = await _get(client, f"{origin}/cacti/", host)
        if alt and ("cacti" in _title(alt[1]).lower() or "cacti.net" in (alt[1] or "").lower()):
            body = alt[1]
        else:
            return None
    ver = _ver(r"[Vv]ersion\s*([0-9]+\.[0-9]+\.[0-9]+)", body) or _ver(r"cacti-version[^0-9]*([0-9.]+)", body)
    # CVE: < 1.2.27 → több súlyos (pl. CVE-2024-25641 tetszőleges fájlírás RCE)
    if _lt(ver, (1, 2, 27)):
        return _f("svc-cacti", "high", "Cacti", ver,
                  "Cacti — sebezhető verzió", "Cacti — vulnerable version",
                  f"Cacti {ver} < 1.2.27 (pl. CVE-2024-25641)", f"Cacti {ver} < 1.2.27 (e.g. CVE-2024-25641)",
                  cve="CVE-2024-25641")
    return _f("svc-cacti", "low", "Cacti", ver,
              "Elérhető Cacti", "Reachable Cacti",
              f"Cacti {ver or '?'} elérhető", f"Cacti {ver or '?'} reachable")


async def _zabbix(client, origin, host=None):
    root = await _get(client, f"{origin}/", host)
    title = _title(root[1]) if root else ""
    if "zabbix" not in title.lower():
        idx = await _get(client, f"{origin}/index.php", host)
        if not (idx and "zabbix" in _title(idx[1]).lower()):
            return None
        root = idx
    ver = _ver(r"[Zz]abbix\s*([0-9]+\.[0-9]+\.[0-9]+)", root[1] if root else "")
    return _f("svc-zabbix", "info", "Zabbix", ver,
              "Elérhető Zabbix", "Reachable Zabbix",
              f"Zabbix {ver or '?'} elérhető", f"Zabbix {ver or '?'} reachable")


async def _netdata(client, origin, host=None):
    r = await _get(client, f"{origin}/api/v1/info", host)
    if not (r and r[0] == 200 and ("version" in r[1].lower()) and ("netdata" in r[1].lower() or '"mirrored_hosts"' in r[1])):
        return None
    ver = _ver(r'"version"\s*:\s*"([^"]+)"', r[1])
    return _f("svc-netdata", "info", "Netdata", ver,
              "Elérhető Netdata", "Reachable Netdata",
              f"Netdata {ver or '?'} elérhető (/api/v1/info)", f"Netdata {ver or '?'} reachable (/api/v1/info)")


async def _prometheus(client, origin, host=None):
    r = await _get(client, f"{origin}/api/v1/status/buildinfo", host)
    if r and r[0] == 200 and '"version"' in r[1] and '"status"' in r[1]:
        ver = _ver(r'"version"\s*:\s*"([^"]+)"', r[1])
        return _f("svc-prometheus", "low", "Prometheus", ver,
                  "Kitett Prometheus", "Exposed Prometheus",
                  f"Prometheus {ver or '?'} (/api/v1/status/buildinfo)",
                  f"Prometheus {ver or '?'} (/api/v1/status/buildinfo)")
    root = await _get(client, f"{origin}/", host)
    if root and root[0] == 200 and "Prometheus" in (root[1] or "") and "Time Series" in (root[1] or ""):
        return _f("svc-prometheus", "low", "Prometheus", "",
                  "Kitett Prometheus", "Exposed Prometheus",
                  "Prometheus felület elérhető", "Prometheus UI reachable")
    return None


async def _portainer(client, origin, host=None):
    r = await _get(client, f"{origin}/api/system/version", host)
    if not (r and r[0] == 200 and '"ServerVersion"' in r[1]):
        r = await _get(client, f"{origin}/api/status", host)
        if not (r and r[0] == 200 and ('"Version"' in r[1])):
            return None
    ver = _ver(r'"(?:ServerVersion|Version)"\s*:\s*"([^"]+)"', r[1])
    return _f("svc-portainer", "info", "Portainer", ver,
              "Elérhető Portainer", "Reachable Portainer",
              f"Portainer {ver or '?'} elérhető", f"Portainer {ver or '?'} reachable")


# Reverse proxy mögötti (80/443 vagy a felderített web-port) telepítésekhez: minden detektor.
_WEB_DETECTORS = [_openwebui, _flowise, _langflow, _n8n, _grafana, _cacti, _zabbix, _ollama, _netdata, _prometheus, _portainer]
# Közvetlen IP:port – a jellemző default portok (proxy nélkül kitett szolgáltatások).
_PORT_DETECTORS = {11434: _ollama, 19999: _netdata, 9090: _prometheus, 9000: _portainer, 9443: _portainer,
                   3000: _grafana, 7860: _langflow, 5678: _n8n, 8080: _openwebui}


def _web_scheme_for(open_ports):
    ports = set(open_ports or [])
    if 443 in ports:
        return "https", 443
    if 80 in ports:
        return "http", 80
    for p in (8443, 8080, 8000, 3000):
        if p in ports:
            return ("https" if p == 8443 else "http"), p
    return None


async def probe_host(client, host: str, ip: str, open_ports: list[int], timeout: float = 6.0) -> list[dict]:
    """Egy host kitett AI/low-code/monitoring eszközeinek felismerése. Dedup termékre."""
    found: dict[str, dict] = {}   # product -> finding

    async def _run(det, origin, hhost):
        try:
            f = await det(client, origin, hhost)
        except Exception:  # noqa: BLE001
            return
        if f and f["product"] not in found:
            found[f["product"]] = f

    # 1) Reverse proxy / sima web (a host nevén, a felderített sémán)
    web = _web_scheme_for(open_ports or [])
    if web:
        scheme, port = web
        base = f"{scheme}://{host}" if port in (80, 443) else f"{scheme}://{host}:{port}"
        for det in _WEB_DETECTORS:
            await _run(det, base, host)

    # 2) Közvetlen IP:port a jellemző default portokon (ha nyitott, és még nincs meg a termék)
    for p, det in _PORT_DETECTORS.items():
        if p in set(open_ports or []) and ip:
            await _run(det, f"http://{ip}:{p}", host)

    return list(found.values())
