"""Passzív gazdagítás és jelzések: ASN/ország (Team Cymru), reverse DNS (PTR), domain-posture
(MX/NS/TXT/CAA/SPF/DMARC/DKIM), wildcard-DNS felismerés, subdomain-takeover heurisztika,
valamint (az aktív fázishoz) technológia-ujjlenyomatozás HTTP-válaszból.

Mind kulcs nélküli és kíméletes: a Cymru ASN-adat DNS-en jön, a posture az authoritatív DNS-ből.
"""
from __future__ import annotations

import asyncio
import ipaddress
import random
import re
import string

from . import netchecks as nc

# ---------------- ASN / ország (Team Cymru, DNS-en) ----------------
async def asn_lookup(ip: str) -> dict | None:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if a.version != 4:
        return None
    rev = ".".join(reversed(ip.split(".")))
    _, recs = await nc.dns_query(f"{rev}.origin.asn.cymru.com", "TXT")
    if not recs:
        return None
    parts = [p.strip() for p in recs[0].split("|")]
    if len(parts) < 3:
        return None
    asn, prefix, cc = parts[0], parts[1], parts[2]
    org = None
    _, arecs = await nc.dns_query(f"AS{asn}.asn.cymru.com", "TXT")
    if arecs:
        ap = [p.strip() for p in arecs[0].split("|")]
        org = ap[-1] if ap else None
    return {"asn": asn, "prefix": prefix, "cc": cc, "org": org}


async def reverse_dns(ip: str) -> str | None:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if a.version != 4:
        return None
    rev = ".".join(reversed(ip.split(".")))
    _, recs = await nc.dns_query(f"{rev}.in-addr.arpa", "PTR")
    return recs[0].rstrip(".") if recs else None


# ---------------- Domain-posture (apex) ----------------
DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "dkim", "mail", "s1", "s2"]


async def domain_posture(domain: str) -> dict:
    out: dict = {}
    async def q(name, qt):
        _, recs = await nc.dns_query(name, qt)
        return recs
    mx, ns, txt, caa, dmarc = await asyncio.gather(
        q(domain, "MX"), q(domain, "NS"), q(domain, "TXT"), q(domain, "CAA"), q(f"_dmarc.{domain}", "TXT"))
    if mx:
        out["mx"] = mx
    if ns:
        out["ns"] = ns
    if caa:
        out["caa"] = caa
    spf = [t for t in txt if t.lower().startswith("v=spf1")]
    out["spf"] = spf[0] if spf else None
    dm = [t for t in dmarc if t.lower().startswith("v=dmarc1")]
    out["dmarc"] = dm[0] if dm else None
    # DKIM: néhány gyakori selector best-effort
    found = []
    async def dk(sel):
        _, recs = await nc.dns_query(f"{sel}._domainkey.{domain}", "TXT")
        if any("dkim1" in r.lower() or "p=" in r for r in recs):
            found.append(sel)
    await asyncio.gather(*(dk(s) for s in DKIM_SELECTORS))
    out["dkim"] = sorted(found)
    # egyszerű értékelés a UI-hoz
    out["spf_ok"] = bool(out["spf"])
    out["dmarc_ok"] = bool(out["dmarc"])
    return out


# ---------------- Wildcard-DNS felismerés ----------------
async def detect_wildcard(domain: str) -> set:
    """Pár véletlen aldomén feloldása; a kapott IP-k a wildcard-címek (üres halmaz = nincs wildcard)."""
    ips: set[str] = set()
    labels = ["".join(random.choice(string.ascii_lowercase) for _ in range(12)) for _ in range(3)]
    for lbl in labels:
        _, a = await nc.dns_query(f"{lbl}.{domain}", "A")
        ips.update(a)
    return ips


# ---------------- Subdomain-takeover ----------------
# (CNAME-részlet, szolgáltatás, opcionális HTTP-ujjlenyomat az aktív megerősítéshez)
TAKEOVER = [
    ("github.io", "GitHub Pages", "There isn't a GitHub Pages site here"),
    ("herokuapp.com", "Heroku", "No such app"),
    ("herokudns.com", "Heroku", "No such app"),
    ("s3.amazonaws.com", "AWS S3", "NoSuchBucket"),
    ("s3-website", "AWS S3", "NoSuchBucket"),
    ("cloudfront.net", "CloudFront", None),
    ("azurewebsites.net", "Azure App Service", "404 Web Site not found"),
    ("cloudapp.net", "Azure", None),
    ("trafficmanager.net", "Azure Traffic Manager", None),
    ("blob.core.windows.net", "Azure Blob", None),
    ("fastly.net", "Fastly", "Fastly error: unknown domain"),
    ("ghost.io", "Ghost", "Domain error"),
    ("wordpress.com", "WordPress", "Do you want to register"),
    ("myshopify.com", "Shopify", "Sorry, this shop is currently unavailable"),
    ("surge.sh", "Surge", "project not found"),
    ("bitbucket.io", "Bitbucket", "Repository not found"),
    ("readthedocs.io", "Read the Docs", "unknown to Read the Docs"),
    ("netlify.app", "Netlify", "Not Found"),
    ("netlify.com", "Netlify", "Not Found"),
    ("pantheonsite.io", "Pantheon", "The gods are wise"),
    ("zendesk.com", "Zendesk", "Help Center Closed"),
    ("wpengine.com", "WP Engine", None),
    ("pages.dev", "Cloudflare Pages", None),
    ("fly.dev", "Fly.io", None),
]


def takeover_candidate(cname: str | None) -> tuple[str, str] | None:
    """A CNAME egy ismert, takeover-érzékeny szolgáltatásra mutat-e. -> (szolgáltatás, cname) vagy None."""
    if not cname:
        return None
    c = cname.lower().rstrip(".")
    for sub, svc, _fp in TAKEOVER:
        if sub in c:
            return svc, c
    return None


def takeover_fingerprint(service: str) -> str | None:
    for _sub, svc, fp in TAKEOVER:
        if svc == service:
            return fp
    return None


# ---------------- Technológia-ujjlenyomat (aktív, HTTP-válaszból) ----------------
_TECH_HEADER = [
    ("x-powered-by", r"(.+)", "{0}"),
    ("server", r"(cloudflare)", "Cloudflare"),
    ("server", r"(nginx)", "nginx"),
    ("server", r"(apache)", "Apache"),
    ("server", r"(microsoft-iis)", "IIS"),
    ("server", r"(litespeed)", "LiteSpeed"),
    ("server", r"(caddy)", "Caddy"),
    ("x-aspnet-version", r"(.+)", "ASP.NET {0}"),
    ("x-drupal-cache", r".*", "Drupal"),
    ("x-generator", r"(.+)", "{0}"),
]
_TECH_BODY = [
    (r"wp-content|wp-includes", "WordPress"),
    (r"Drupal.settings|sites/default/files", "Drupal"),
    (r"/media/jui/|Joomla!", "Joomla"),
    (r"__NEXT_DATA__", "Next.js"),
    (r"ng-version=", "Angular"),
    (r"data-reactroot|react-dom", "React"),
    (r"window\.__NUXT__", "Nuxt.js"),
    (r"csrfmiddlewaretoken", "Django"),
    (r"Laravel|laravel_session", "Laravel"),
    (r"X-Shopify|cdn\.shopify\.com", "Shopify"),
    (r"wix\.com|_wixCIDX", "Wix"),
    (r"gatsby", "Gatsby"),
]


def detect_tech(headers: dict, body: str) -> list[str]:
    tech: list[str] = []
    h = {k.lower(): str(v) for k, v in (headers or {}).items()}
    for key, pat, label in _TECH_HEADER:
        if key in h:
            m = re.search(pat, h[key], re.I)
            if m:
                tech.append(label.format(*(m.groups() or ("",))).strip())
    b = body or ""
    for pat, label in _TECH_BODY:
        if re.search(pat, b, re.I):
            tech.append(label)
    # egyedi, sorrendtartó
    seen, out = set(), []
    for t in tech:
        if t and t.lower() not in seen:
            seen.add(t.lower())
            out.append(t)
    return out[:12]
