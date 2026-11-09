"""Alkalmazás-szintű, kíméletes higiénia-jelzések (az infra-recon kiegészítése).

Három kör, mind GET-only, engedélyezett célponton, nem kihasználás:
  1. OIDC/OAuth metaadat (`/.well-known/openid-configuration` stb.) → hirdetett gyenge beállítások:
     implicit flow, PKCE (S256) hiánya, 'none' vagy szimmetrikus (HS*) id_token-aláírás,
     dinamikus kliensregisztráció hirdetése. Csak a nyilvános metaadatot OLVASSA, flow-t nem játszik.
  2. Security-fejléc + cookie-flag hiányok a gyökér válaszból (CSP, Referrer-Policy, clickjacking-védelem,
     cookie Secure/HttpOnly/SameSite).
  3. Open-redirect próba — EZ AKTÍV (preparált paramétert küld egy ÁRTALMATLAN külső kanárira, és csak a
     `Location`-t nézi, nem követi). Ezért ALAPBÓL KI van kapcsolva: csak `RECON_OPEN_REDIRECT=1` env mellett
     fut, és KIZÁRÓLAG engedélyezett célponton szabad bekapcsolni.

A findingök a `vulncheck._xf` kétnyelvű formátumát használják, és a motor a `d["vuln"]` listába fűzi őket,
így a meglévő UI/riport változtatás nélkül megjeleníti.
"""
from __future__ import annotations

import json
import os
import re
from urllib.parse import quote, urlsplit

from .vulncheck import _web_scheme_for, _xf

_MAX = 65536          # legfeljebb ennyi bájtot olvasunk
_CANARY = "example.org"       # ártalmatlan külső cél az open-redirect próbához (RFC 2606 / IANA minta)
_AUTH_HINT = re.compile(r"(oauth|openam|openid|auth|sso|login|idp|account|connect|realms)", re.I)
# az open-redirectnél vizsgált, magas eséllyel visszairányító paraméternevek
_REDIR_PARAMS = ["redirect_uri", "redirect", "redirect_url", "returnUrl", "return",
                 "url", "next", "goto", "RelayState"]


async def _geth(client, url: str, host: str | None = None, timeout: float = 6.0):
    """Biztonságos GET fejlécekkel: (status, text, headers_lower, set_cookies, location) vagy None.
    Átirányítást nem követ (a hívó kliens follow_redirects=False), max ~64 KB-ot olvas."""
    try:
        headers = {"Host": host} if host else None
        r = await client.get(url, headers=headers, timeout=timeout)
        raw = r.content[:_MAX] if r.content else b""
        text = raw.decode("utf-8", "replace")
        hdrs = {k.lower(): v for k, v in r.headers.items()}
        try:
            cookies = r.headers.get_list("set-cookie")
        except Exception:  # noqa: BLE001
            one = r.headers.get("set-cookie")
            cookies = [one] if one else []
        return r.status_code, text, hdrs, cookies, str(r.headers.get("location", "") or "")
    except Exception:  # noqa: BLE001
        return None


# ------------------------------------------- OIDC metaadat -------------------------------------------
async def _fetch_oidc(client, base: str, host: str, timeout: float):
    """A nyilvános OIDC/OAuth metaadat (dict) + authorization_endpoint, vagy (None, '')."""
    paths = ["/.well-known/openid-configuration"]
    if _AUTH_HINT.search(host or ""):          # auth-jellegű hoszton több, terméksajátos útvonalat is nézünk
        paths += ["/.well-known/oauth-authorization-server",
                  "/openam/oauth2/.well-known/openid-configuration",
                  "/oauth2/.well-known/openid-configuration"]
    for p in paths:
        res = await _geth(client, base + p, host=host, timeout=timeout)
        if not res or res[0] != 200:
            continue
        try:
            j = json.loads(res[1])
        except Exception:  # noqa: BLE001
            continue
        if isinstance(j, dict) and (j.get("issuer") or j.get("response_types_supported")
                                    or j.get("authorization_endpoint")):
            return j, str(j.get("authorization_endpoint") or "")
    return None, ""


def _oidc_findings(j: dict) -> list[dict]:
    out: list[dict] = []
    rts = [str(x).lower() for x in (j.get("response_types_supported") or [])]
    if any("token" in rt for rt in rts):       # implicit vagy hibrid flow engedélyezett
        out.append(_xf("oidc-implicit", "medium",
            "OIDC: implicit/hibrid flow engedélyezett", "OIDC: implicit/hybrid flow enabled",
            f"response_types_supported: {', '.join(rts)}",
            f"response_types_supported: {', '.join(rts)}"))
    ccm = j.get("code_challenge_methods_supported")
    if not ccm or "S256" not in [str(x) for x in ccm]:
        out.append(_xf("oidc-no-pkce", "medium",
            "OIDC: PKCE (S256) nincs hirdetve", "OIDC: PKCE (S256) not advertised",
            f"code_challenge_methods_supported: {ccm}",
            f"code_challenge_methods_supported: {ccm}"))
    algs = [str(x).lower() for x in (j.get("id_token_signing_alg_values_supported") or [])]
    if "none" in algs:
        out.append(_xf("oidc-alg-none", "high",
            "OIDC: 'none' id_token-aláírás engedélyezett", "OIDC: 'none' id_token signing allowed",
            "id_token_signing_alg_values_supported tartalmaz: none",
            "id_token_signing_alg_values_supported contains: none"))
    hs = [a for a in algs if a.startswith("hs")]
    if hs:
        out.append(_xf("oidc-hs-signing", "low",
            "OIDC: szimmetrikus (HS*) id_token-aláírás", "OIDC: symmetric (HS*) id_token signing",
            f"alg: {', '.join(hs)}", f"alg: {', '.join(hs)}"))
    if j.get("registration_endpoint"):
        out.append(_xf("oidc-dynreg", "low",
            "OIDC: dinamikus kliensregisztráció hirdetve", "OIDC: dynamic client registration advertised",
            f"registration_endpoint: {j.get('registration_endpoint')}",
            f"registration_endpoint: {j.get('registration_endpoint')}"))
    return out


# ---------------------------------------- fejléc + cookie ----------------------------------------
def _header_findings(hdrs: dict, cookies: list[str], scheme: str) -> list[dict]:
    out: list[dict] = []
    csp = hdrs.get("content-security-policy", "") or ""
    if not csp:
        out.append(_xf("no-csp", "low",
            "Hiányzó Content-Security-Policy", "Missing Content-Security-Policy",
            "nincs CSP válasz-fejléc", "no CSP response header"))
    if not hdrs.get("referrer-policy"):
        out.append(_xf("no-referrer-policy", "low",
            "Hiányzó Referrer-Policy", "Missing Referrer-Policy",
            "nincs Referrer-Policy (token/kód szivároghat a Refererben)",
            "no Referrer-Policy (token/code may leak via Referer)"))
    if not hdrs.get("x-frame-options") and "frame-ancestors" not in csp.lower():
        out.append(_xf("no-clickjacking", "medium",
            "Hiányzó clickjacking-védelem (X-Frame-Options / frame-ancestors)",
            "Missing clickjacking protection (X-Frame-Options / frame-ancestors)",
            "nincs X-Frame-Options és nincs CSP frame-ancestors",
            "no X-Frame-Options and no CSP frame-ancestors"))
    seen: set[str] = set()
    for c in cookies or []:
        cl = c.lower()
        name = c.split("=", 1)[0].strip()[:40]
        if scheme == "https" and "secure" not in cl and "secure" not in seen:
            seen.add("secure")
            out.append(_xf("cookie-no-secure", "medium",
                "Cookie Secure jelző nélkül", "Cookie without Secure flag",
                f"Set-Cookie {name}: nincs Secure", f"Set-Cookie {name}: no Secure"))
        if "httponly" not in cl and "httponly" not in seen:
            seen.add("httponly")
            out.append(_xf("cookie-no-httponly", "low",
                "Cookie HttpOnly nélkül", "Cookie without HttpOnly",
                f"Set-Cookie {name}: nincs HttpOnly", f"Set-Cookie {name}: no HttpOnly"))
        if "samesite" not in cl and "samesite" not in seen:
            seen.add("samesite")
            out.append(_xf("cookie-no-samesite", "low",
                "Cookie SameSite nélkül", "Cookie without SameSite",
                f"Set-Cookie {name}: nincs SameSite", f"Set-Cookie {name}: no SameSite"))
    return out


# -------------------------------- open redirect (AKTÍV, alapból KI) --------------------------------
def _host_of(loc: str) -> str:
    if not loc:
        return ""
    if loc.startswith("//"):
        loc = "https:" + loc
    try:
        return (urlsplit(loc).hostname or "").lower()
    except Exception:  # noqa: BLE001
        return ""


async def _open_redirect(client, base: str, host: str, auth_ep: str, timeout: float) -> list[dict]:
    """Preparált redirect-paraméter → ha a Location a külső kanárira mutat, open redirect.
    AKTÍV próba: csak RECON_OPEN_REDIRECT=1 és engedélyezett célpont mellett hívjuk."""
    canary = f"https://{_CANARY}/"
    targets = [base + "/"]
    if auth_ep:
        targets.append(auth_ep if auth_ep.startswith("http") else base + auth_ep)
    for turl in targets[:2]:
        for pn in _REDIR_PARAMS:
            sep = "&" if "?" in turl else "?"
            res = await _geth(client, f"{turl}{sep}{pn}={quote(canary, safe='')}", host=host, timeout=timeout)
            if not res:
                continue
            if 300 <= res[0] < 400 and _host_of(res[4]) == _CANARY:
                return [_xf("open-redirect", "high",
                    "Nyitott átirányítás (open redirect)", "Open redirect",
                    f"GET {turl} ?{pn}=<külső> → Location: {res[4][:120]}",
                    f"GET {turl} ?{pn}=<external> → Location: {res[4][:120]}")]
    return []


# ------------------------------------------- belépő -------------------------------------------
async def app_findings(client, host: str, ip: str, open_ports: list[int], timeout: float = 6.0) -> list[dict]:
    """GET-only app-higiénia findingök egy hostra. Üres lista, ha nincs web-port vagy nincs jelzés."""
    web = _web_scheme_for(open_ports or [])
    if not web:
        return []
    scheme, port = web
    base = f"{scheme}://{host}" if port in (80, 443) else f"{scheme}://{host}:{port}"
    findings: list[dict] = []

    root = await _geth(client, base + "/", host=host, timeout=timeout)
    if root:
        findings += _header_findings(root[2], root[3], scheme)

    meta, auth_ep = await _fetch_oidc(client, base, host, timeout)
    if meta is not None:
        findings += _oidc_findings(meta)

    if os.getenv("RECON_OPEN_REDIRECT") == "1":          # AKTÍV, csak engedéllyel
        try:
            findings += await _open_redirect(client, base, host, auth_ep, timeout)
        except Exception:  # noqa: BLE001
            pass

    return findings
