"""SEO / AI-láthatóság fázis.

Két rész:
  1) candidates(): a leltár hostjaiból – új kérés nélkül – rangsorolt jelöltlista: melyik host valószínűleg
     nyilvános, keresőnek szánt webhely (apex/www, 200-as HTML, értelmes cím), és melyik nem (csak IP,
     nem webes, bejelentkezés, alapértelmezett oldal, infrastruktúra-név). Az azonos webhelyre mutatókat
     összevonja.
  2) audit_site() / quick_site(): egy webhely kívülről mérhető SEO- és AI-láthatósági ellenőrzése
     GET-kérésekkel (átirányítás-mátrix, meta, canonical, hreflang, robots/sitemap/llms.txt, JSON-LD,
     tartalom JS nélkül, AI-crawlerek hozzáférése, 404). Kíméletes: soros kérések, saját User-Agent,
     a robots.txt-t a saját UA-ra betartja, a bot-UA-s próba botonként egyetlen, jelölt diagnosztikai kérés.

Finding-shape (mint a többi fázisé): {id, cat, severity, title, title_en, evidence, evidence_en}.
Nem kihasználás, nem tölt ki űrlapot, nem jelentkezik be.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import secrets
import socket
import time
from html.parser import HTMLParser
from urllib import robotparser
from urllib.parse import urljoin, urlsplit, urlunsplit
from xml.etree import ElementTree as ET

import httpx

from . import __version__

UA = f"domain-recon-seo/{__version__} (+https://github.com/krisztianhari-wq/domain-recon)"
BROWSER_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/141.0 Safari/537.36")
BODY_MAX = 2_000_000
TIMEOUT = 10.0
PAUSE = 0.35                 # két kérés között ugyanarra a webhelyre (kíméletesség)
MAX_FULL = 10                # teljes audit legfeljebb ennyi webhelyre egy futásban
MAX_QUICK = 30               # gyors átfutás legfeljebb ennyi jelöltre
MAX_HREFLANG_FETCH = 6

SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}

# ---------------------------------------------------------------- AI- és keresőbotok
# (token, gyártó, cél, User-Agent a diagnosztikai próbához vagy None = csak robots-token)
# cél: training = modell-tanítás, search = keresési index, user = felhasználó által indított élő lekérés.
# A UA-k a gyártói dokumentáció mintái (rövidítve); a WAF-próba csak jelzés, nem bizonyíték.
BOTS = [
    ("Googlebot", "Google", "search", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"),
    ("Bingbot", "Microsoft", "search", "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"),
    ("GPTBot", "OpenAI", "training", "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.1; +https://openai.com/gptbot"),
    ("OAI-SearchBot", "OpenAI", "search", "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; OAI-SearchBot/1.0; +https://openai.com/searchbot"),
    ("ChatGPT-User", "OpenAI", "user", None),
    ("ClaudeBot", "Anthropic", "training", "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; +claudebot@anthropic.com)"),
    ("Claude-SearchBot", "Anthropic", "search", "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Claude-SearchBot/1.0; +https://www.anthropic.com)"),
    ("Claude-User", "Anthropic", "user", None),
    ("PerplexityBot", "Perplexity", "search", "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)"),
    ("Perplexity-User", "Perplexity", "user", None),
    ("Google-Extended", "Google", "training", None),
    ("Applebot-Extended", "Apple", "training", None),
    ("meta-externalagent", "Meta", "training", None),
    ("CCBot", "Common Crawl", "training", "CCBot/2.0 (https://commoncrawl.org/faq/)"),
    ("Bytespider", "ByteDance", "training", None),
]
PROBE_LIMIT = 8

# ---------------------------------------------------------------- jelölt-heurisztika
INFRA_RE = re.compile(
    r"^(mail\d*|webmail|smtp\d*|imap|pop3?|mx\d*|autodiscover|autoconfig|owa|exchange|lyncdiscover|sip|"
    r"vpn\d*|remote|rdp|citrix|gw|gateway|fw|firewall|sso|idp|adfs|auth|login|api\d*|cdn\d*|static|assets|"
    r"img|media|ns\d*|dns\d*|ftp|sftp|ntp|ldap|radius|proxy|monitor|grafana|zabbix|nagios|jira|confluence|"
    r"git|gitlab|jenkins|ci|vault|backup|nas|cpanel|whm|plesk|portal-admin|admin)$")
DEVLIKE_RE = re.compile(r"^(dev|test|stage|staging|uat|qa|preprod|sandbox|demo|beta)\d*$")
MARKETING_RE = re.compile(r"^(www\d*|shop|store|webshop|blog|news|hirek|karrier|careers|jobs|info|"
                          r"[a-z]{2}-[a-z]{2})$")     # 2 betűs címke szándékosan nem (ai., it. stb. félrevinne)
LOGIN_RE = re.compile(r"\b(log ?in|sign ?in|bejelentkez|belépés|single sign|sso|outlook web|"
                      r"anmeld|connexion|authenticat)", re.I)
LOGIN_PATH_RE = re.compile(r"(login|signin|sign_in|sign-in|oauth|sso|auth|interaction|authorize|saml|adfs)", re.I)
DEFAULT_RE = re.compile(r"(welcome to nginx|apache2? (ubuntu|debian)? ?default page|it works!|iis windows server|"
                        r"test page for|default web site page|domain (is )?for sale|parked|coming soon|"
                        r"index of /|403 forbidden|404 not found|plesk|cpanel)", re.I)
NONSEO_TECH = {"exchange", "owa", "citrix", "fortinet", "fortigate", "palo alto", "globalprotect", "pulse secure",
               "ivanti", "grafana", "kibana", "zabbix", "jenkins", "gitlab", "jira", "confluence", "sonicwall",
               "f5 big-ip", "vmware", "roundcube", "zimbra"}
WEB_TECH = {"wordpress", "drupal", "joomla", "shopify", "wix", "squarespace", "webflow", "next.js", "nuxt",
            "gatsby", "hubspot", "magento", "woocommerce", "prestashop", "typo3", "ghost"}


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s.strip("[]"))
        return True
    except ValueError:
        return False


def _label(host: str, domain: str) -> str:
    """A domain alatti első címke (pl. shop.example.com → 'shop'; apex → '')."""
    if not domain or host == domain:
        return ""
    if host.endswith("." + domain):
        return host[: -len(domain) - 1].split(".")[-1]
    return host.split(".")[0]


def _host_http(d: dict) -> list[dict]:
    out = []
    for p in d.get("ports") or []:
        h = p.get("http")
        if h:
            out.append({**h, "port": p.get("port")})
    return out


def _site_key(host: str, https: list[dict]) -> str:
    """Összevonási kulcs: az átirányítás célhostja (www nélkül), különben a host maga (www nélkül)."""
    for h in https:
        loc = h.get("location") or ""
        if h.get("status") in (301, 302, 303, 307, 308) and loc.startswith("http"):
            tgt = (urlsplit(loc).hostname or "").lower()
            if tgt:
                return tgt[4:] if tgt.startswith("www.") else tgt
    return host[4:] if host.startswith("www.") else host


def candidates(hosts: list[dict], domain: str = "") -> dict:
    """Rangsorolt SEO-jelöltlista a leltárból, új kérés nélkül.

    -> {"candidates": [{host, url, score, reasons[], default, site, members[]}], "excluded": [{host, reason}]}
    """
    domain = (domain or "").lower()
    excluded, scored = [], []
    for d in hosts:
        host = (d.get("host") or "").lower().rstrip(".")
        if not host:
            continue
        if _is_ip(host):
            excluded.append({"host": host, "reason": "ip", "why": "csak IP-cím, nincs hostnév",
                             "why_en": "bare IP address, no hostname"})
            continue
        if not d.get("alive"):
            excluded.append({"host": host, "reason": "dead", "why": "nem él (nincs DNS-válasz)",
                             "why_en": "not alive (no DNS answer)"})
            continue
        lab = _label(host, domain)
        https = _host_http(d)
        have_ports = bool(d.get("ports"))
        score, reasons = 0, []
        is_apex = bool(domain) and host in (domain, "www." + domain)
        if is_apex:
            score += 60
            reasons.append(("a domain fő webhelye (apex/www)", "main site of the domain (apex/www)"))
        if INFRA_RE.match(lab):
            excluded.append({"host": host, "reason": "infra", "why": f"infrastruktúra-név ({lab})",
                             "why_en": f"infrastructure name ({lab})"})
            continue
        if DEVLIKE_RE.match(lab):
            score -= 25
            reasons.append(("fejlesztői/teszt-név", "dev/test-like name"))
        if MARKETING_RE.match(lab) and not is_apex:
            score += 15
            reasons.append(("marketing-jellegű név", "marketing-like name"))
        if have_ports and not https:
            excluded.append({"host": host, "reason": "noweb", "why": "nincs webes válasz a nyitott portokon",
                             "why_en": "no HTTP response on open ports"})
            continue
        best = None
        for h in https:
            if h.get("port") in (443, 80) and (best is None or (h.get("status") or 999) < (best.get("status") or 999)):
                best = h
        best = best or (https[0] if https else None)
        if best:
            st = best.get("status") or 0
            title = best.get("title") or ""
            tech = {str(t).lower() for t in (best.get("tech") or [])}
            ctype = best.get("ctype") or ""
            if st in (401, 403, 407):
                excluded.append({"host": host, "reason": "auth", "why": f"hozzáférés tiltva ({st})",
                                 "why_en": f"access denied ({st})"})
                continue
            if tech & NONSEO_TECH:
                excluded.append({"host": host, "reason": "app", "why": "alkalmazás/eszköz: " + ", ".join(sorted(tech & NONSEO_TECH)),
                                 "why_en": "application/appliance: " + ", ".join(sorted(tech & NONSEO_TECH))})
                continue
            if title and LOGIN_RE.search(title):
                excluded.append({"host": host, "reason": "login", "why": f"bejelentkező oldal („{title[:60]}”)",
                                 "why_en": f"login page (“{title[:60]}”)"})
                continue
            if title and DEFAULT_RE.search(title):
                excluded.append({"host": host, "reason": "default", "why": f"alapértelmezett/parkoló oldal („{title[:60]}”)",
                                 "why_en": f"default/parked page (“{title[:60]}”)"})
                continue
            if ctype and "html" not in ctype and st == 200:
                excluded.append({"host": host, "reason": "nonhtml", "why": f"nem HTML válasz ({ctype})",
                                 "why_en": f"non-HTML response ({ctype})"})
                continue
            if st == 200:
                score += 20
                reasons.append(("200-as válasz", "HTTP 200"))
            elif 300 <= st < 400:
                score += 5
                reasons.append(("átirányít", "redirects"))
            elif st >= 500:
                score -= 10
                reasons.append((f"szerverhiba ({st})", f"server error ({st})"))
            if title and len(title) >= 4:
                score += 10
                reasons.append(("van értelmes cím", "has a meaningful title"))
            if tech & WEB_TECH:
                score += 15
                reasons.append(("webes CMS/keretrendszer: " + ", ".join(sorted(tech & WEB_TECH)),
                                "web CMS/framework: " + ", ".join(sorted(tech & WEB_TECH))))
        elif not have_ports:
            reasons.append(("nincs aktív adat (az aktív fázis nem futott)", "no active data (active phase not run)"))
        scored.append({"host": host, "score": score, "reasons": reasons, "site": _site_key(host, https),
                       "https": any(h.get("scheme") == "https" for h in https) or not https})

    # összevonás webhelyenként: a legjobb pontszámú host képviseli
    sites: dict[str, dict] = {}
    for c in scored:
        cur = sites.get(c["site"])
        if cur is None or c["score"] > cur["score"] or (c["score"] == cur["score"] and len(c["host"]) < len(cur["host"])):
            members = (cur or {}).get("members", [])
            if cur:
                members = members + [cur["host"]]
            sites[c["site"]] = {**c, "members": members}
        else:
            cur["members"].append(c["host"])
    out = []
    for s in sorted(sites.values(), key=lambda x: (-x["score"], x["host"])):
        host = s["host"]
        out.append({
            "host": host, "url": f"https://{host}/", "score": s["score"], "site": s["site"],
            "members": sorted(set(s["members"]) - {host}),
            "reasons": [r[0] for r in s["reasons"]], "reasons_en": [r[1] for r in s["reasons"]],
            "default": False,
        })
    # alapból: a fő webhely (apex/www csoport), ha van; különben a legjobb jelölt, ha elég erős
    main = next((c for c in out if domain and c["site"] in (domain,) ), None)
    if main:
        main["default"] = True
    elif out and out[0]["score"] >= 30:
        out[0]["default"] = True
    return {"candidates": out, "excluded": sorted(excluded, key=lambda x: (x["reason"], x["host"]))}


# ---------------------------------------------------------------- HTML-elemzés (stdlib)
class _Page(HTMLParser):
    VOID_SKIP = {"script", "style", "noscript", "template", "svg"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title = None
        self._in_title = False
        self.metas: list[dict] = []
        self.links: list[dict] = []
        self.anchors: list[str] = []
        self.imgs: list[dict] = []
        self.headings: list[tuple[int, str]] = []
        self._h: int | None = None
        self._htxt: list[str] = []
        self.jsonld: list[str] = []
        self._ld = False
        self._ldbuf: list[str] = []
        self._skip = 0
        self.text: list[str] = []
        self.html_lang = None
        self.nosnippet = False
        self.srcs: list[str] = []
        self.spa_root = False
        self.password = False

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if "data-nosnippet" in a:
            self.nosnippet = True
        if tag == "html":
            self.html_lang = a.get("lang") or None
        elif tag == "title" and self.title is None:
            self._in_title = True
            self._tbuf = []
        elif tag == "meta":
            self.metas.append(a)
        elif tag == "link":
            self.links.append(a)
        elif tag == "a" and a.get("href"):
            self.anchors.append(a["href"])
        elif tag == "img":
            self.imgs.append(a)
            if a.get("src"):
                self.srcs.append(a["src"])
        elif tag in ("script", "iframe", "source", "video", "audio") and a.get("src"):
            self.srcs.append(a["src"])
        elif tag in ("h1", "h2", "h3", "h4", "h5", "h6"):
            self._h = int(tag[1])
            self._htxt = []
        elif tag == "input" and a.get("type", "").lower() == "password":
            self.password = True
        elif tag == "div" and a.get("id") in ("root", "app", "__next", "__nuxt"):
            self.spa_root = True
        if tag == "script" and "ld+json" in a.get("type", "").lower():
            self._ld = True
            self._ldbuf = []
        if tag in self.VOID_SKIP:
            self._skip += 1

    def handle_endtag(self, tag):
        if tag == "title" and self._in_title:
            self._in_title = False
            self.title = re.sub(r"\s+", " ", "".join(self._tbuf)).strip()
        elif tag in ("h1", "h2", "h3", "h4", "h5", "h6") and self._h:
            self.headings.append((self._h, re.sub(r"\s+", " ", "".join(self._htxt)).strip()[:120]))
            self._h = None
        if tag == "script" and self._ld:
            self._ld = False
            self.jsonld.append("".join(self._ldbuf))
        if tag in self.VOID_SKIP and self._skip:
            self._skip -= 1

    def handle_data(self, data):
        if self._in_title:
            self._tbuf.append(data)
        if self._ld:
            self._ldbuf.append(data)
            return
        if self._h:
            self._htxt.append(data)
        if not self._skip:
            self.text.append(data)

    # ---- kényelmi lekérdezők
    def meta(self, name: str) -> str | None:
        name = name.lower()
        for m in self.metas:
            if (m.get("name") or m.get("property") or "").lower() == name:
                return m.get("content", "")
        return None

    def link_rel(self, rel: str) -> list[dict]:
        return [l for l in self.links if rel in (l.get("rel") or "").lower().split()]

    def visible_text(self) -> str:
        return re.sub(r"\s+", " ", " ".join(self.text)).strip()


def parse_html(html: str) -> _Page:
    p = _Page()
    try:
        p.feed(html)
        p.close()
    except Exception:  # noqa: BLE001  – hibás HTML: amit eddig kinyert, az marad
        pass
    return p


# ---------------------------------------------------------------- JSON-LD szabályok
LB_TYPES = {"LocalBusiness", "Bakery", "Restaurant", "CafeOrCoffeeShop", "Store", "FoodEstablishment",
            "BarOrPub", "Dentist", "MedicalBusiness", "AutoRepair", "HealthAndBeautyBusiness", "LegalService",
            "ProfessionalService", "HomeAndConstructionBusiness", "LodgingBusiness", "Hotel", "SportsActivityLocation",
            "EntertainmentBusiness", "FinancialService", "RealEstateAgent", "TravelAgency", "ClothingStore",
            "GroceryStore", "ElectronicsStore", "Pharmacy", "Optician", "BeautySalon", "HairSalon"}
NOT_RICH = {"FAQPage", "HowTo"}      # a Google rich result gyűjteményében már nem szerepel (2026)


def _ld_items(raw_blocks: list[str]) -> tuple[list[dict], list[str]]:
    items, errors = [], []
    for raw in raw_blocks:
        txt = raw.strip()
        if not txt:
            continue
        try:
            data = json.loads(txt)
        except ValueError as e:
            errors.append(str(e)[:120])
            continue
        stack = data if isinstance(data, list) else [data]
        while stack:
            x = stack.pop()
            if isinstance(x, dict):
                if "@graph" in x and isinstance(x["@graph"], list):
                    stack.extend(x["@graph"])
                if "@type" in x:
                    items.append(x)
            elif isinstance(x, list):
                stack.extend(x)
    return items, errors


def _types(it: dict) -> set[str]:
    t = it.get("@type")
    return set(t) if isinstance(t, list) else {t} if isinstance(t, str) else set()


def jsonld_findings(raw_blocks: list[str], visible: str) -> tuple[list[dict], dict]:
    items, errors = _ld_items(raw_blocks)
    fs: list[dict] = []
    types = sorted({t for it in items for t in _types(it)})
    facts = {"jsonld_blocks": len(raw_blocks), "jsonld_types": types}
    for e in errors:
        fs.append(_f("ld_invalid", "schema", "high", "Hibás JSON-LD blokk", "Invalid JSON-LD block",
                     f"A JSON nem értelmezhető: {e}", f"JSON could not be parsed: {e}"))
    if not raw_blocks:
        fs.append(_f("ld_none", "schema", "medium", "Nincs strukturált adat (JSON-LD)", "No structured data (JSON-LD)",
                     "A főoldalon nincs application/ld+json blokk (szervezet, helyi vállalkozás, termék…).",
                     "The home page has no application/ld+json block (Organization, LocalBusiness, Product…)."))
        return fs, facts
    vis = visible.lower()
    for it in items:
        ts = _types(it)
        if ts & NOT_RICH:
            t = ", ".join(sorted(ts & NOT_RICH))
            fs.append(_f("ld_notrich", "schema", "info", f"{t}: nem ad Google rich resultot",
                         f"{t}: no longer a Google rich result",
                         f"A {t} típus 2026-ban nem szerepel a Google rich result gyűjteményében; nem hiba, csak nem hoz megjelenést.",
                         f"{t} is not in Google's rich result gallery in 2026; not an error, it just brings no enhanced result."))
        if ts & LB_TYPES or "Organization" in ts:
            kind = "LocalBusiness" if ts & LB_TYPES else "Organization"
            req = ["name"] + (["address"] if kind == "LocalBusiness" else [])
            rec = (["telephone", "geo", "openingHoursSpecification", "url", "image", "priceRange"]
                   if kind == "LocalBusiness" else ["url", "logo", "sameAs"])
            miss_req = [k for k in req if not it.get(k)]
            miss_rec = [k for k in rec if not it.get(k) and not (k == "openingHoursSpecification" and it.get("openingHours"))]
            if miss_req:
                fs.append(_f("ld_req", "schema", "high", f"{kind}: hiányzó kötelező mező", f"{kind}: missing required property",
                             "Hiányzik: " + ", ".join(miss_req), "Missing: " + ", ".join(miss_req)))
            if miss_rec:
                fs.append(_f("ld_rec", "schema", "low", f"{kind}: hiányzó ajánlott mezők", f"{kind}: missing recommended properties",
                             "Ajánlott, de hiányzik: " + ", ".join(miss_rec) + ". Csak valós, hivatalos adattal töltsd ki.",
                             "Recommended but missing: " + ", ".join(miss_rec) + ". Fill in only with real, official data."))
            tel = it.get("telephone")
            if isinstance(tel, str) and tel and re.sub(r"\D", "", tel)[-7:] not in re.sub(r"\D", "", visible):
                fs.append(_f("ld_tel_vis", "schema", "medium", "A JSON-LD telefonszám nem látszik az oldalon",
                             "JSON-LD telephone not visible on the page",
                             f"„{tel}” a strukturált adatban van, a látható szövegben nem; a jelölésnek egyeznie kell a látható tartalommal.",
                             f"“{tel}” is in the markup but not in the visible text; markup must match visible content."))
            name = it.get("name")
            if isinstance(name, str) and name and name.lower() not in vis:
                fs.append(_f("ld_name_vis", "schema", "low", "A JSON-LD név nem látszik az oldalon",
                             "JSON-LD name not visible on the page", f"„{name}”", f"“{name}”"))
        if "Product" in ts:
            offers = it.get("offers")
            offers = offers if isinstance(offers, list) else [offers] if isinstance(offers, dict) else []
            if not offers:
                fs.append(_f("ld_prod_offer", "schema", "medium", "Product: nincs ajánlat (offers)", "Product: no offers",
                             f"„{it.get('name', '?')}”", f"“{it.get('name', '?')}”"))
            for o in offers[:3]:
                miss = [k for k in ("price", "priceCurrency") if not o.get(k)]
                if miss:
                    fs.append(_f("ld_offer", "schema", "medium", "Offer: hiányzó ár-mező", "Offer: missing price field",
                                 "Hiányzik: " + ", ".join(miss), "Missing: " + ", ".join(miss)))
                    break
    return fs, facts


# ---------------------------------------------------------------- segédek
def _f(fid, cat, sev, title, title_en, ev="", ev_en=""):
    return {"id": fid, "cat": cat, "severity": sev, "title": title, "title_en": title_en,
            "evidence": ev, "evidence_en": ev_en or ev}


HREFLANG_RE = re.compile(r"^(x-default|[a-z]{2,3}(-[A-Za-z]{4})?(-([A-Za-z]{2}|\d{3}))?)$", re.I)
BAD_REGION = {"uk": "gb"}       # en-UK → en-GB


def hreflang_problems(code: str) -> str | None:
    c = code.strip()
    if not HREFLANG_RE.match(c):
        return "érvénytelen formátum"
    parts = c.lower().split("-")
    if len(parts) >= 2 and parts[-1] in BAD_REGION:
        return f"rossz régiókód ({parts[-1].upper()} → {BAD_REGION[parts[-1]].upper()})"
    return None


def robots_policy(robots_txt: str, url: str) -> list[dict]:
    """Botonként: engedi-e a robots.txt az adott URL-t."""
    rp = robotparser.RobotFileParser()
    rp.parse(robots_txt.splitlines())
    out = []
    for token, vendor, purpose, ua in BOTS:
        try:
            ok = rp.can_fetch(token, url)
        except Exception:  # noqa: BLE001
            ok = True
        out.append({"bot": token, "vendor": vendor, "purpose": purpose, "allowed": ok, "probe": bool(ua)})
    return out


def _norm_url(u: str) -> str:
    s = urlsplit(u)
    path = s.path or "/"
    return urlunsplit((s.scheme.lower(), (s.hostname or "").lower() + (f":{s.port}" if s.port else ""), path, s.query, ""))


CHALLENGE_RE = re.compile(r"(cf-chl|challenge-platform|just a moment|attention required|captcha|"
                          r"access denied|request blocked|bot detection|ddos protection)", re.I)


class _Fetcher:
    """Kíméletes, SSRF-védett lekérő: kézi átirányítás-követés, minden ugrásnál a célcím ellenőrzése."""

    def __init__(self, client: httpx.AsyncClient, allow_ip, pause: float = PAUSE):
        self.c = client
        self.allow_ip = allow_ip
        self.pause = pause
        self.count = 0
        self._last = 0.0
        self._dns: dict[str, bool] = {}

    async def _host_ok(self, host: str) -> bool:
        if host in self._dns:
            return self._dns[host]
        ok = False
        try:
            infos = await asyncio.get_running_loop().getaddrinfo(host, None, type=socket.SOCK_STREAM)
            ips = {i[4][0] for i in infos}
            ok = bool(ips) and all(self.allow_ip(ip) for ip in ips)
        except OSError:
            ok = False
        self._dns[host] = ok
        return ok

    async def get(self, url: str, ua: str = UA, follow: bool = True, max_hops: int = 6,
                  accept: str = "text/html,application/xhtml+xml,*/*;q=0.8") -> dict:
        chain = []
        cur = url
        for _ in range(max_hops + 1):
            host = urlsplit(cur).hostname or ""
            if not host or not await self._host_ok(host):
                return {"url": cur, "error": "blocked_or_unresolvable", "chain": chain}
            wait = self.pause - (time.monotonic() - self._last)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last = time.monotonic()
            self.count += 1
            try:
                async with self.c.stream("GET", cur, headers={"User-Agent": ua, "Accept": accept},
                                         follow_redirects=False) as r:
                    body = b""
                    if not (300 <= r.status_code < 400):
                        async for chunk in r.aiter_bytes():
                            body += chunk
                            if len(body) >= BODY_MAX:
                                break
                    hdrs = {k.lower(): v for k, v in r.headers.items()}
                    status = r.status_code
            except httpx.HTTPError as e:
                return {"url": cur, "error": e.__class__.__name__, "chain": chain}
            if 300 <= status < 400 and follow and hdrs.get("location"):
                nxt = urljoin(cur, hdrs["location"])
                chain.append({"url": cur, "status": status, "to": nxt})
                if any(_norm_url(c["url"]) == _norm_url(nxt) for c in chain):
                    return {"url": nxt, "error": "redirect_loop", "chain": chain}
                cur = nxt
                continue
            enc = r.encoding or "utf-8"
            try:
                text = body.decode(enc, "replace")
            except LookupError:
                text = body.decode("utf-8", "replace")
            return {"url": cur, "status": status, "headers": hdrs, "text": text, "size": len(body), "chain": chain}
        return {"url": cur, "error": "too_many_redirects", "chain": chain}


def _variants(url: str) -> list[str]:
    s = urlsplit(url)
    host = (s.hostname or "").lower()
    bare = host[4:] if host.startswith("www.") else host
    hosts = [bare, "www." + bare] if bare.count(".") >= 1 else [host]
    return [f"{sc}://{h}/" for sc in ("http", "https") for h in hosts]


# ---------------------------------------------------------------- gyors átfutás
async def quick_site(fx: _Fetcher, url: str) -> dict:
    r = await fx.get(url)
    res = {"url": url, "mode": "quick", "findings": [], "facts": {}}
    if r.get("error"):
        res["facts"]["error"] = r["error"]
        res["findings"].append(_f("unreachable", "access", "high", "Nem érhető el", "Not reachable", r["error"]))
        return res
    p = parse_html(r.get("text", "")) if "html" in r["headers"].get("content-type", "") else _Page()
    robots_meta = (p.meta("robots") or "") + " " + r["headers"].get("x-robots-tag", "")
    canon = p.link_rel("canonical")
    words = len(p.visible_text().split())
    res["final_url"] = r["url"]
    src_host, dst = (urlsplit(url).hostname or ""), urlsplit(r["url"])
    moved = (dst.hostname or "") not in (src_host, "www." + src_host, src_host.removeprefix("www."))
    res["facts"] = {"status": r["status"], "title": p.title, "noindex": "noindex" in robots_meta.lower(),
                    "canonical": canon[0].get("href") if canon else None, "words_nojs": words,
                    "hops": len(r["chain"]), "redirected_to": dst.hostname if moved else None}
    if p.password or (p.title and LOGIN_RE.search(p.title)) or (moved and LOGIN_PATH_RE.search(dst.path + "?" + dst.query)):
        res["facts"]["login"] = True
        res["findings"].append(_f("login", "access", "info", "Bejelentkezés mögött (nem nyilvános webhely)",
                                  "Behind a login (not a public website)", r["url"][:120]))
        return res
    if moved:
        res["findings"].append(_f("moved", "redirect", "info", f"Másik hostra irányít ({dst.hostname})",
                                  f"Redirects to another host ({dst.hostname})", r["url"][:120]))
    if r["status"] >= 400:
        res["findings"].append(_f("status", "access", "high", f"Hibás státusz ({r['status']})", f"Error status ({r['status']})", r["url"]))
    if res["facts"]["noindex"]:
        res["findings"].append(_f("noindex", "access", "medium", "noindex: nem kerül a keresőbe", "noindex: kept out of search",
                                  robots_meta.strip()[:120]))
    if not p.title:
        res["findings"].append(_f("title_missing", "meta", "medium", "Nincs <title>", "No <title>"))
    if words < 80 and r["status"] == 200:
        res["findings"].append(_f("thin_nojs", "content", "medium", "Szinte üres JS nélkül", "Nearly empty without JS",
                                  f"{words} szó a nyers HTML-ben.", f"{words} words in the raw HTML."))
    return res


# ---------------------------------------------------------------- teljes audit
async def audit_site(fx: _Fetcher, url: str, progress=None) -> dict:
    F: list[dict] = []
    facts: dict = {}
    step = (lambda s: progress(s)) if progress else (lambda s: None)

    # 1) átirányítás-mátrix
    step("redirects")
    finals = {}
    for v in _variants(url):
        r = await fx.get(v)
        finals[v] = {"final": r.get("url"), "status": r.get("status"), "hops": len(r.get("chain", [])),
                     "error": r.get("error"), "chain": [c["status"] for c in r.get("chain", [])]}
    facts["variants"] = finals
    ok_finals = {_norm_url(x["final"]) for x in finals.values() if x["final"] and not x["error"] and (x["status"] or 0) < 400}
    https_main = [x for k, x in finals.items() if k.startswith("https") and not x["error"] and (x["status"] or 0) < 400]
    if not https_main:
        F.append(_f("https_fail", "redirect", "high", "HTTPS-en nem érhető el", "Not reachable over HTTPS",
                    "; ".join(f"{k}: {x['error'] or x['status']}" for k, x in finals.items() if k.startswith("https"))))
    for k, x in finals.items():
        if k.startswith("http://") and x["final"] and x["final"].startswith("http://") and not x["error"]:
            F.append(_f("no_https_redirect", "redirect", "high", "HTTP nem irányít HTTPS-re", "HTTP does not redirect to HTTPS", k))
        if x["hops"] > 2:
            F.append(_f("long_chain", "redirect", "medium", f"Hosszú átirányítás-lánc ({x['hops']} ugrás)",
                        f"Long redirect chain ({x['hops']} hops)", f"{k} → {x['final']} ({', '.join(map(str, x['chain']))})"))
        if x["chain"] and any(c in (302, 303, 307) for c in x["chain"]):
            F.append(_f("temp_redirect", "redirect", "low", "Ideiglenes (302/307) átirányítás állandó helyett",
                        "Temporary (302/307) redirect instead of permanent", f"{k}: {', '.join(map(str, x['chain']))}"))
    if len(ok_finals) > 1:
        F.append(_f("multi_final", "redirect", "medium", "A változatok nem egy kanonikus címre futnak",
                    "Variants do not converge on one canonical URL", ", ".join(sorted(ok_finals))))

    # 2) főoldal
    step("home")
    home_url = next(iter(sorted(ok_finals)), url) if ok_finals else url
    h = await fx.get(home_url)
    if h.get("error") or (h.get("status") or 0) >= 400:
        F.append(_f("home_fail", "access", "high", "A főoldal nem tölthető be", "Home page failed to load",
                    f"{home_url}: {h.get('error') or h.get('status')}"))
        return _finish(url, home_url, F, facts, fx)
    home_url = h["url"]
    hd = h["headers"]
    ctype = hd.get("content-type", "")
    p = parse_html(h["text"]) if "html" in ctype else _Page()
    vis = p.visible_text()
    words = len(vis.split())
    facts.update({"final_url": home_url, "status": h["status"], "content_type": ctype, "bytes": h["size"],
                  "title": p.title, "words_nojs": words, "lang": p.html_lang})

    # meta
    step("meta")
    robots_meta = " ".join(filter(None, [p.meta("robots"), p.meta("googlebot")])).lower()
    xrt = hd.get("x-robots-tag", "").lower()
    if "noindex" in robots_meta or "noindex" in xrt:
        F.append(_f("noindex_home", "access", "high", "A főoldal noindex", "Home page is noindex",
                    (robots_meta + " " + xrt).strip()[:160]))
    if any(x in robots_meta + xrt for x in ("nosnippet", "max-snippet:0")) or p.nosnippet:
        F.append(_f("nosnippet", "access", "medium", "Snippet-tiltás (AI-összefoglalókból is kimarad)",
                    "Snippet restriction (also excluded from AI summaries)", (robots_meta + " " + xrt).strip()[:160] or "data-nosnippet"))
    if not p.title:
        F.append(_f("title_missing", "meta", "high", "Nincs <title>", "No <title>"))
    elif not (15 <= len(p.title) <= 65):
        F.append(_f("title_len", "meta", "low", f"A cím hossza {len(p.title)} karakter", f"Title length {len(p.title)} characters",
                    "Ajánlott ~15–60 karakter (gyakorlati irányelv).", "Recommended ~15–60 characters (practice, not a Google rule).")
                 | {"evidence": f"„{p.title}” – ajánlott ~15–60 karakter (gyakorlati irányelv).",
                    "evidence_en": f"“{p.title}” – recommended ~15–60 characters (practice, not a Google rule)."})
    desc = p.meta("description")
    if not desc:
        F.append(_f("desc_missing", "meta", "medium", "Nincs meta description", "No meta description"))
    elif not (50 <= len(desc) <= 170):
        F.append(_f("desc_len", "meta", "low", f"A leírás hossza {len(desc)} karakter", f"Description length {len(desc)} characters",
                    "Ajánlott ~70–160 karakter.", "Recommended ~70–160 characters."))
    if not p.html_lang:
        F.append(_f("lang_missing", "meta", "medium", "Nincs <html lang>", "No <html lang>"))
    if p.meta("viewport") is None:
        F.append(_f("viewport", "meta", "medium", "Nincs viewport meta (mobil)", "No viewport meta (mobile)"))
    og_missing = [k for k in ("og:title", "og:description", "og:image") if not p.meta(k)]
    if og_missing:
        F.append(_f("og", "meta", "low", "Hiányos Open Graph", "Incomplete Open Graph", ", ".join(og_missing)))
    h1 = [t for lv, t in p.headings if lv == 1]
    if len(h1) != 1:
        F.append(_f("h1", "meta", "medium", f"{len(h1)} db <h1>", f"{len(h1)} <h1> elements", "Pontosan egy ajánlott.", "Exactly one recommended."))
    prev = 0
    for lv, t in p.headings:
        if prev and lv > prev + 1:
            F.append(_f("h_skip", "meta", "low", "Kihagyott címsorszint", "Skipped heading level", f"h{prev} → h{lv} („{t[:50]}”)",
                        f"h{prev} → h{lv} (“{t[:50]}”)"))
            break
        prev = lv

    # canonical
    canon = p.link_rel("canonical")
    facts["canonical"] = [c.get("href") for c in canon]
    if not canon:
        F.append(_f("canon_missing", "canonical", "medium", "Nincs rel=canonical", "No rel=canonical"))
    elif len(canon) > 1:
        F.append(_f("canon_multi", "canonical", "high", f"{len(canon)} db canonical", f"{len(canon)} canonical tags",
                    ", ".join(c.get("href", "") for c in canon)))
    else:
        ch = canon[0].get("href", "")
        if not ch.startswith("http"):
            F.append(_f("canon_rel", "canonical", "low", "Relatív canonical", "Relative canonical", ch))
        ca = _norm_url(urljoin(home_url, ch))
        if ca != _norm_url(home_url):
            F.append(_f("canon_other", "canonical", "medium", "A főoldal canonicalja máshová mutat", "Home canonical points elsewhere",
                        f"{home_url} → {ca}"))

    # mixed content
    if home_url.startswith("https://"):
        mixed = [s for s in p.srcs if s.startswith("http://")]
        if mixed:
            F.append(_f("mixed", "canonical", "medium", "Vegyes tartalom (http:// erőforrás https oldalon)",
                        "Mixed content (http:// resource on an https page)", ", ".join(mixed[:3])))

    # tartalom JS nélkül
    step("content")
    if words < 150:
        sev = "high" if words < 60 else "medium"
        spa = " (SPA-gyökérelem, valószínűleg kliensoldali renderelés)" if p.spa_root else ""
        F.append(_f("thin_nojs", "content", sev, "Kevés szöveg JS nélkül", "Little text without JS",
                    f"{words} szó a nyers HTML-ben{spa}. Az AI-crawlerek többsége nem futtat JavaScriptet.",
                    f"{words} words in the raw HTML{' (SPA root element, likely client-side rendering)' if p.spa_root else ''}. Most AI crawlers do not run JavaScript."))
    phone = re.search(r"(\+\d[\d\s().-]{7,}\d)", vis)
    price = re.search(r"(€\s?\d|\d[\d.,]*\s?(€|eur|ft|huf|usd|\$))", vis, re.I)
    tel_links = [a for a in p.anchors if a.startswith("tel:")]
    facts["nojs_signals"] = {"phone": bool(phone), "price": bool(price), "tel_link": bool(tel_links),
                             "mailto": any(a.startswith("mailto:") for a in p.anchors)}

    # képek
    imgs = p.imgs
    no_alt = [i.get("src", "")[:80] for i in imgs if "alt" not in i]
    no_dim = [i for i in imgs if not (i.get("width") and i.get("height"))]
    facts["images"] = {"count": len(imgs), "no_alt": len(no_alt), "no_dimensions": len(no_dim),
                       "srcset": sum(1 for i in imgs if i.get("srcset"))}
    if no_alt:
        F.append(_f("img_alt", "images", "medium", f"{len(no_alt)} képen nincs alt", f"{len(no_alt)} images lack alt",
                    ", ".join(no_alt[:3])))
    if imgs and len(no_dim) == len(imgs) and len(imgs) >= 3:
        F.append(_f("img_dim", "images", "low", "Egyik képen sincs width/height", "No image has width/height",
                    "CLS-kockázat, ha a CSS sem ad képarányt (aspect-ratio).", "CLS risk unless CSS sets an aspect-ratio."))

    # strukturált adat
    step("schema")
    lf, lfacts = jsonld_findings(p.jsonld, vis)
    F += lf
    facts.update(lfacts)

    # hreflang
    step("hreflang")
    alts = [(l.get("hreflang", ""), urljoin(home_url, l.get("href", ""))) for l in p.link_rel("alternate") if l.get("hreflang")]
    facts["hreflang"] = [{"lang": a, "href": u} for a, u in alts]
    if alts:
        for code, _u in alts:
            prob = hreflang_problems(code)
            if prob:
                F.append(_f("hl_code", "i18n", "medium", f"Hibás hreflang-kód: {code}", f"Invalid hreflang code: {code}", prob))
        if not any(_norm_url(u) == _norm_url(home_url) for _c, u in alts):
            F.append(_f("hl_self", "i18n", "medium", "A hreflang-halmazból hiányzik az önhivatkozás",
                        "hreflang set lacks a self-reference", home_url))
        if not any(c.lower() == "x-default" for c, _u in alts):
            F.append(_f("hl_xdef", "i18n", "low", "Nincs x-default hreflang", "No x-default hreflang"))
        checked = 0
        for code, u in alts:
            if _norm_url(u) == _norm_url(home_url) or checked >= MAX_HREFLANG_FETCH:
                continue
            checked += 1
            r = await fx.get(u, follow=False)
            if r.get("error") or r.get("status") != 200:
                F.append(_f("hl_target", "i18n", "high", f"hreflang-cél nem 200 ({code})", f"hreflang target not 200 ({code})",
                            f"{u}: {r.get('error') or r.get('status')}"))
                continue
            q = parse_html(r.get("text", ""))
            back = [urljoin(u, l.get("href", "")) for l in q.link_rel("alternate") if l.get("hreflang")]
            if not any(_norm_url(b) == _norm_url(home_url) for b in back):
                F.append(_f("hl_recip", "i18n", "high", f"Nem kölcsönös hreflang ({code})", f"Non-reciprocal hreflang ({code})",
                            f"{u} nem hivatkozik vissza erre: {home_url}", f"{u} does not link back to {home_url}"))
            qc = q.link_rel("canonical")
            if qc and _norm_url(urljoin(u, qc[0].get("href", ""))) != _norm_url(u):
                F.append(_f("hl_canon", "i18n", "high", f"A nyelvi változat canonicalja máshová mutat ({code})",
                            f"Language version canonical points elsewhere ({code})", f"{u} → {qc[0].get('href')}"))

    # robots / sitemap / llms.txt / 404
    step("files")
    origin = f"{urlsplit(home_url).scheme}://{urlsplit(home_url).netloc}"
    rb = await fx.get(origin + "/robots.txt", accept="text/plain,*/*")
    robots_txt = ""
    if rb.get("error") or (rb.get("status") or 0) >= 500:
        F.append(_f("robots_5xx", "access", "high", "robots.txt szerverhibát ad", "robots.txt returns a server error",
                    f"{rb.get('error') or rb.get('status')} – a Google ilyenkor felfüggesztheti a bejárást.",
                    f"{rb.get('error') or rb.get('status')} – Google may pause crawling."))
    elif rb.get("status") == 200:
        robots_txt = rb.get("text", "")
        if rb.get("size", 0) > 500 * 1024:
            F.append(_f("robots_big", "access", "medium", "robots.txt nagyobb 500 KiB-nál", "robots.txt larger than 500 KiB"))
    else:
        F.append(_f("robots_none", "access", "low", "Nincs robots.txt", "No robots.txt", f"{rb.get('status')}"))
    facts["robots"] = {"status": rb.get("status"), "bytes": rb.get("size")}
    rp = robotparser.RobotFileParser()
    rp.parse(robots_txt.splitlines())
    if robots_txt and not rp.can_fetch("Googlebot", home_url):
        F.append(_f("robots_block_home", "access", "high", "A robots.txt tiltja a főoldalt a Googlebotnak",
                    "robots.txt blocks the home page for Googlebot"))
    smaps = re.findall(r"(?im)^\s*sitemap:\s*(\S+)", robots_txt)
    facts["sitemaps_declared"] = smaps
    sm_url = smaps[0] if smaps else origin + "/sitemap.xml"
    sm = await fx.get(sm_url, accept="application/xml,text/xml,*/*")
    sm_facts = {"url": sm_url, "status": sm.get("status")}
    if sm.get("status") == 200:
        try:
            root = ET.fromstring(sm.get("text", "").encode("utf-8", "replace"))
            ns = {"s": "http://www.sitemaps.org/schemas/sitemap/0.9"}
            locs = [e.text.strip() for e in root.iterfind(".//s:loc", ns) if e.text]
            lastmods = [e.text.strip() for e in root.iterfind(".//s:lastmod", ns) if e.text]
            sm_facts.update({"kind": root.tag.split("}")[-1], "urls": len(locs), "lastmod": len(lastmods),
                             "lastmod_uniform": len(set(lastmods)) == 1 and len(lastmods) > 3})
            if locs and any(u.startswith("http://") for u in locs) and home_url.startswith("https://"):
                F.append(_f("sm_http", "access", "medium", "A sitemap http:// URL-eket tartalmaz", "Sitemap contains http:// URLs"))
            if sm_facts["kind"] == "urlset" and locs and not lastmods:
                F.append(_f("sm_lastmod", "access", "low", "A sitemapban nincs lastmod", "Sitemap has no lastmod"))
            if sm_facts.get("lastmod_uniform"):
                F.append(_f("sm_lastmod_uniform", "access", "low", "Minden lastmod azonos (gyanús)", "All lastmod values identical (suspicious)"))
        except ET.ParseError as e:
            F.append(_f("sm_parse", "access", "medium", "A sitemap nem érvényes XML", "Sitemap is not valid XML", str(e)[:120]))
    else:
        F.append(_f("sm_none", "access", "medium" if not smaps else "high", "Nincs elérhető sitemap", "No reachable sitemap",
                    f"{sm_url}: {sm.get('error') or sm.get('status')}"))
    if not smaps and sm.get("status") == 200:
        F.append(_f("sm_undeclared", "access", "low", "A sitemap nincs a robots.txt-ben", "Sitemap not declared in robots.txt"))
    facts["sitemap"] = sm_facts

    ll = await fx.get(origin + "/llms.txt", accept="text/plain,text/markdown,*/*", follow=False)
    llms = {"status": ll.get("status")}
    if ll.get("status") == 200:
        txt = ll.get("text", "")
        llms.update({"bytes": ll.get("size"), "h1": txt.lstrip().startswith("# "),
                     "html": "<html" in txt[:500].lower()})
        if llms["html"]:
            F.append(_f("llms_html", "ai", "low", "Az llms.txt HTML-t ad vissza", "llms.txt returns HTML",
                        "Valószínűleg egy általános oldal válaszol rá (soft 404).", "Probably a catch-all page answers it (soft 404)."))
    else:
        F.append(_f("llms_none", "ai", "info", "Nincs llms.txt", "No llms.txt",
                    "Tájékoztató: a Google Search nem használja; egyes AI-eszközök igen.",
                    "Informational: Google Search does not use it; some AI tools do."))
    facts["llms_txt"] = llms

    rnd = f"{origin}/{secrets.token_hex(6)}-nonexistent"
    nf = await fx.get(rnd, follow=False)
    facts["status_404_test"] = nf.get("status")
    if nf.get("status") == 200:
        F.append(_f("soft404", "access", "medium", "Soft 404: nem létező URL is 200-at ad", "Soft 404: a non-existent URL returns 200", rnd))

    # AI-crawlerek
    step("ai_bots")
    pol = robots_policy(robots_txt, home_url) if robots_txt else [
        {"bot": t, "vendor": v, "purpose": pu, "allowed": True, "probe": bool(ua)} for t, v, pu, ua in BOTS]
    blocked = [b for b in pol if not b["allowed"]]
    if any(b["purpose"] == "search" and not b["allowed"] for b in pol):
        names = ", ".join(b["bot"] for b in pol if b["purpose"] == "search" and not b["allowed"])
        F.append(_f("ai_search_blocked", "ai", "high", "Keresőbot tiltva a robots.txt-ben", "Search bot blocked in robots.txt",
                    f"{names}: ezek nélkül az oldal nem jelenik meg az adott (AI-)keresőben.",
                    f"{names}: without these the site does not appear in that (AI) search."))
    tr_blocked = [b["bot"] for b in pol if b["purpose"] == "training" and not b["allowed"]]
    if tr_blocked:
        F.append(_f("ai_training_blocked", "ai", "info", "Tanító botok tiltva (szándékos döntés lehet)",
                    "Training bots blocked (may be intentional)", ", ".join(tr_blocked)))
    base = await fx.get(home_url, ua=BROWSER_UA, follow=False)
    base_len = base.get("size") or 0
    probes = []
    for tok, vendor, purpose, ua in BOTS:
        if not ua or len(probes) >= PROBE_LIMIT:
            continue
        if not next((b["allowed"] for b in pol if b["bot"] == tok), True):
            continue                                  # robots-ban tiltott botot nem próbálunk
        r = await fx.get(home_url, ua=ua, follow=False)
        st = r.get("status")
        size = r.get("size") or 0
        txt = (r.get("text") or "")[:20000]
        verdict = "ok"
        if r.get("error"):
            verdict = "error"
        elif st == 402:
            verdict = "pay_per_crawl"
        elif st in (403, 429, 503) and base.get("status") == 200:
            verdict = "likely_blocked"
        elif st == 200 and base_len and size < base_len * 0.3 and CHALLENGE_RE.search(txt):
            verdict = "challenge"
        probes.append({"bot": tok, "vendor": vendor, "purpose": purpose, "status": st, "bytes": size, "verdict": verdict})
    facts["ai_bots"] = {"robots": pol, "probes": probes, "baseline_status": base.get("status"), "baseline_bytes": base_len,
                        "cdn": next((v for k, v in (("cf-ray", "Cloudflare"), ("x-akamai-transformed", "Akamai"),
                                                    ("x-served-by", "Fastly")) if k in (base.get("headers") or {})), None)}
    bad = [x for x in probes if x["verdict"] in ("likely_blocked", "challenge", "pay_per_crawl")]
    for x in bad:
        if x["verdict"] == "pay_per_crawl":
            F.append(_f("ai_402", "ai", "medium", f"{x['bot']}: 402 (pay per crawl)", f"{x['bot']}: 402 (pay per crawl)",
                        "A CDN fizetést kér az AI-bottól.", "The CDN asks the AI bot to pay."))
        else:
            sev = "high" if x["purpose"] == "search" else "medium"
            F.append(_f("ai_waf", "ai", sev, f"{x['bot']}: valószínű WAF/CDN-blokk", f"{x['bot']}: likely WAF/CDN block",
                        f"Böngésző-UA: {base.get('status')} ({base_len} B), {x['bot']}-UA: {x['status']} ({x['bytes']} B). "
                        "Jelzés, nem bizonyíték: a CDN az IP-t is ellenőrzi, az igazi bot átmehet.",
                        f"Browser UA: {base.get('status')} ({base_len} B), {x['bot']} UA: {x['status']} ({x['bytes']} B). "
                        "Indication, not proof: the CDN also verifies IPs, the real bot may get through."))
    facts["robots_blocked_bots"] = [b["bot"] for b in blocked]

    # fejléc-higiénia (nem számít a pontszámba)
    if home_url.startswith("https://") and "strict-transport-security" not in hd:
        F.append(_f("hsts", "headers", "low", "Nincs HSTS", "No HSTS"))
    if not hd.get("content-encoding") and h["size"] > 50_000:
        F.append(_f("compress", "headers", "low", "Tömörítetlen HTML", "Uncompressed HTML",
                    f"{h['size']} bájt gzip/br nélkül.", f"{h['size']} bytes without gzip/br."))
    return _finish(url, home_url, F, facts, fx)


CAT_WEIGHT = {"access": 3, "redirect": 2, "canonical": 2, "meta": 2, "content": 3, "schema": 2, "i18n": 2,
              "images": 1, "ai": 2}
SEV_PENALTY = {"high": 40, "medium": 20, "low": 5, "info": 0}
CATS = ["access", "redirect", "canonical", "meta", "content", "schema", "i18n", "images", "ai", "headers"]


def score(findings: list[dict]) -> dict:
    cats = {}
    for c in CAT_WEIGHT:
        pen = sum(SEV_PENALTY.get(f["severity"], 0) for f in findings if f.get("cat") == c)
        cats[c] = max(0, 100 - pen)
    tot = sum(CAT_WEIGHT.values())
    overall = round(sum(cats[c] * w for c, w in CAT_WEIGHT.items()) / tot)
    return {"overall": overall, "by_cat": cats}


def _finish(url, home_url, F, facts, fx) -> dict:
    F.sort(key=lambda f: (SEV_ORDER.get(f["severity"], 9), CATS.index(f["cat"]) if f["cat"] in CATS else 99))
    return {"url": url, "final_url": home_url, "mode": "full", "findings": F, "facts": facts,
            "score": score(F), "requests": fx.count}
