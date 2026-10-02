"""domain-recon – FastAPI. Írj be egy domaint → aldomének, hostok, élő/nem élő, portok, szolgáltatások.

Hitelesítést a fordított proxy (oauth2-proxy/passkey) ad; ez az app egy megbízható felhasználót szolgál ki.
Védelem: TrustedHost, szigorú CSP, kéréstörzs-limit, egyidejű vizsgálatok korlátja, domain-validáció.
"""
from __future__ import annotations

import asyncio
import csv
import hmac
import io
import json
import os
import re
import secrets
import time

from fastapi import Body, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles

from . import engine
from .db import DB
from .ports import resolve_profile

HERE = os.path.dirname(__file__)
STATIC = os.path.join(HERE, "static")
DATA = os.getenv("RECON_DATA", os.path.join(os.path.dirname(HERE), "data"))
ALLOWED = [h.strip() for h in os.getenv("RECON_ALLOWED_HOSTS", "").split(",") if h.strip()]
MAX_SCANS = int(os.getenv("RECON_MAX_CONCURRENCY", "2"))
KEEP = int(os.getenv("RECON_KEEP", "60"))
MAX_BODY = 4096
PROXY_SECRET = os.getenv("RECON_PROXY_SECRET", "")   # ha be van állítva, csak a Caddy X-Recon-Proxy fejlécét fogadjuk el

HOST_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$")

db = DB(os.path.join(DATA, "recon.db"))
app = FastAPI(title="domain-recon", docs_url=None, redoc_url=None, openapi_url=None)

CSP = ("default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
       "font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
SEC_HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
}


@app.middleware("http")
async def guard(request: Request, call_next):
    # a /healthz mindig átmegy (belső konténer-healthcheck, tetszőleges Host, proxy-titok nélkül)
    if request.url.path == "/healthz":
        return await call_next(request)
    # mélységi védelem: csak a fordított proxy (Caddy) közös titkát hordozó kérés megy át
    if PROXY_SECRET:
        if not hmac.compare_digest(request.headers.get("x-recon-proxy", ""), PROXY_SECRET):
            return PlainTextResponse("forbidden", status_code=403)
    # Host-fejléc ellenőrzés (ha konfigurálva)
    if ALLOWED:
        host = (request.headers.get("host") or "").split(":")[0]
        if host and host not in ALLOWED:
            return PlainTextResponse("bad host", status_code=400)
    # kéréstörzs-limit
    cl = request.headers.get("content-length")
    if cl and cl.isdigit() and int(cl) > MAX_BODY:
        return PlainTextResponse("payload too large", status_code=413)
    resp = await call_next(request)
    for k, v in SEC_HEADERS.items():
        resp.headers.setdefault(k, v)
    return resp


app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.get("/")
async def index():
    return FileResponse(os.path.join(STATIC, "index.html"))


@app.get("/healthz")
async def healthz():
    return PlainTextResponse("ok")


@app.get("/robots.txt")
async def robots():
    return PlainTextResponse("User-agent: *\nDisallow: /\n")


def _norm_domain(raw: str) -> str:
    d = (raw or "").strip().lower().rstrip(".")[:253]   # hosszkorlát a regex előtt (ReDoS-védelem)
    d = re.sub(r"^https?://", "", d)
    d = d.split("/")[0].split(":")[0]
    try:
        d = d.encode("idna").decode("ascii")
    except Exception:  # noqa: BLE001
        pass
    if not HOST_RE.match(d):
        raise HTTPException(400, "Érvénytelen domain.")
    return d


@app.post("/api/scan")
async def api_scan(payload: dict = Body(...)):
    running = sum(1 for s in db.recent_scans(MAX_SCANS * 3) if s["status"] in ("queued", "running"))
    if running >= MAX_SCANS:
        raise HTTPException(429, f"Már {running} vizsgálat fut. Várd meg, amíg befejeződik.")
    domain = _norm_domain(payload.get("domain", ""))
    ports = str(payload.get("ports", "service"))
    custom = str(payload.get("custom_ports", ""))[:2000]
    _, pname = resolve_profile(ports, custom)
    opts = {
        "ports": ports, "custom_ports": custom, "profile": pname,
        "intensity": payload.get("intensity", "polite") if payload.get("intensity") in engine.INTENSITY else "polite",
        "ct": bool(payload.get("ct", True)),
        "wordlist": bool(payload.get("wordlist", False)),
        "scan_ports": bool(payload.get("scan_ports", True)),
        "allow_private": bool(payload.get("allow_private", False)),
    }
    scan_id = secrets.token_hex(8)
    db.create_scan(scan_id, domain, opts)
    db.prune(KEEP)
    engine.start_scan(db, scan_id, domain, opts)
    return {"id": scan_id, "domain": domain, "opts": opts}


@app.get("/api/scans")
async def api_scans():
    return {"scans": db.recent_scans(40)}


@app.get("/api/scan/{scan_id}")
async def api_scan_get(scan_id: str):
    s = db.get_scan(scan_id)
    if not s:
        raise HTTPException(404, "Nincs ilyen vizsgálat.")
    s["hosts"] = db.hosts(scan_id)
    s["now"] = int(time.time())
    return JSONResponse(s)


@app.post("/api/scan/{scan_id}/cancel")
async def api_scan_cancel(scan_id: str):
    if not db.get_scan(scan_id):
        raise HTTPException(404, "Nincs ilyen vizsgálat.")
    ok = engine.cancel_scan(scan_id)
    return {"canceled": ok}


@app.delete("/api/scan/{scan_id}")
async def api_scan_delete(scan_id: str):
    if not db.get_scan(scan_id):
        raise HTTPException(404, "Nincs ilyen vizsgálat.")
    engine.cancel_scan(scan_id)
    db.delete_scan(scan_id)
    return {"deleted": True}


@app.get("/api/export/{scan_id}.json")
async def api_export_json(scan_id: str):
    s = db.get_scan(scan_id)
    if not s:
        raise HTTPException(404, "Nincs ilyen vizsgálat.")
    s["hosts"] = db.hosts(scan_id)
    data = json.dumps(s, ensure_ascii=False, indent=2)
    return Response(data, media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="recon_{s["domain"]}_{scan_id}.json"'})


def _csv_safe(v) -> str:
    """CSV-képletinjekció ellen: a =,+,-,@ (és vezető tab/CR) kezdetű cellát aposztróffal semlegesítjük."""
    s = "" if v is None else str(v)
    if s and s[0] in "=+-@\t\r":
        return "'" + s
    return s


@app.get("/api/export/{scan_id}.csv")
async def api_export_csv(scan_id: str):
    s = db.get_scan(scan_id)
    if not s:
        raise HTTPException(404, "Nincs ilyen vizsgálat.")
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["# domain-recon", s["domain"], scan_id, time.strftime("%Y-%m-%d %H:%M", time.localtime(s["created"]))])
    w.writerow(["host", "alive", "ips", "cname", "port", "service", "http_status", "server", "title", "tls_cn", "banner"])
    for h in db.hosts(scan_id):
        ips = " ".join(h.get("ips", []))
        if h.get("ports"):
            for p in h["ports"]:
                http = p.get("http") or {}
                tls = p.get("tls") or {}
                w.writerow([_csv_safe(x) for x in [
                    h["host"], "yes" if h.get("alive") else "no", ips, h.get("cname") or "",
                    p["port"], p.get("name", ""), http.get("status", ""), http.get("server", ""),
                    http.get("title", ""), tls.get("cn", ""), (p.get("banner") or "")[:120]]])
        else:
            w.writerow([_csv_safe(x) for x in [
                h["host"], "yes" if h.get("alive") else "no", ips, h.get("cname") or "", "", "", "", "", "", "", ""]])
    return Response(buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="recon_{s["domain"]}_{scan_id}.csv"'})
