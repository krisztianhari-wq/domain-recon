# domain-recon

Type in a domain — **domain-recon** enumerates its subdomains, resolves the hosts
(live / dead), maps open ports and services, and gives you a clean, filterable list.
FastAPI + SQLite, a sadrobot-styled dashboard, HU/EN, light/dark theme, a relationship
graph, and standalone desktop apps for macOS and Windows.

> ⚠️ **Only scan targets you are authorised to.** Port scanning — especially the full
> (1–65535) scan — is an active operation that is visible on the target. The active phase
> must be started explicitly; the responsibility for running it is yours.

## Two phases

**Passive** (runs by default, does not touch the target directly):
- **Subdomain enumeration** from multiple public sources: Certificate Transparency
  (certSpotter, crt.sh), passive-DNS aggregators (Anubis, HackerTarget) and the Wayback archive.
- **Wildcard-DNS detection** (so `*.` catch-all records don't produce fake hosts).
- **DNS resolution** (A / AAAA / CNAME) → live / dead.
- **Enrichment**: reverse DNS (PTR) and ASN / country / organisation (Team Cymru), per IP.
- **DNS & email posture** of the apex: MX, NS, TXT, CAA, **SPF, DMARC, DKIM**.
- **Subdomain-takeover heuristic** (dangling CNAME to a known third-party service).

**Active** (started with a separate button — touches the target):
- **Port scan** (TCP connect): profiles `service` · `common` (~1100) · `full` (1–65535) · `custom`
  (e.g. `22,80,443,8000-8100`); intensity `polite` / `normal` / `aggressive`.
- **Service & technology fingerprinting**: banner grab, HTTP status / `Server` / `X-Powered-By` /
  `<title>`, TLS certificate CN / SAN (SANs often reveal new names), and a tech signature set
  (WordPress, Drupal, Next.js, Laravel, nginx, Cloudflare, …).
- **Takeover confirmation** (HTTP body fingerprint on the suspected hosts).
- **Exposure / misconfiguration checks** (safe, GET-only): exposed `.git` / `.env`, directory
  listing, open Elasticsearch / Kibana / Grafana / Prometheus, Spring actuator, and risky exposed
  services (databases, RDP, SMB, Redis, …).
- Optional **DNS brute-force** with a built-in prefix wordlist.

**SEO / AI visibility** (separate button, narrow scope by design):
- Runs on **selected websites only**, not on every discovered IP. A ranked candidate list is built
  from the inventory **without extra requests**: the apex/www site is pre-selected; bare IPs, dead
  hosts, infrastructure names (`mail`, `vpn`, `autodiscover`, `api`…), login pages, 401/403, default or
  parked pages, non-HTML responses and known appliances are excluded, and hosts that redirect to the
  same site are merged. Every exclusion is listed with its reason. Manual URLs are accepted only for
  hosts in the inventory or under the scanned domain.
- **Full audit** (~20–40 polite, sequential GETs per site, own User-Agent): HTTP/HTTPS × www redirect
  matrix, status, `noindex` / `X-Robots-Tag` / snippet restrictions, title / description / `lang` /
  viewport / Open Graph / heading order, canonical, mixed content, **text and key data visible
  without JavaScript**, images (alt, dimensions), **JSON-LD** (validity, types, required/recommended
  properties, consistency with visible text, types Google no longer shows as rich results),
  **hreflang** (codes, self-reference, reciprocity, canonical of each language version), robots.txt,
  sitemap, llms.txt (informational), soft-404 test, and **AI crawler access**: per-bot robots.txt
  policy (training vs. search vs. user-triggered fetch) and one diagnostic request per allowed bot
  User-Agent to spot likely WAF/CDN blocks or HTTP 402 pay-per-crawl (an indication, not proof).
  Category scores plus a 0–100 overall score; header hygiene is reported but not scored.
- Optional **quick pass** on the other candidates (status, title, `noindex`, text without JS, login detection).
- Not measurable from outside and stated in the report: indexed pages, rankings/CTR, backlinks,
  business profiles, real AI citations, actual bot traffic.

Results are filterable (host / IP / ASN / service, and live / exposed / takeover / dead), each finding
has a **hover tooltip** explaining what it is, and everything is exportable to **CSV / JSON**. A
**relationship graph** (domain ↔ host ↔ IP ↔ ASN) is one click away.

## Install (desktop app)

Download the latest build from the [Releases](https://github.com/krisztianhari-wq/domain-recon/releases)
page. The app runs locally and opens in your browser; **your own machine is the vantage point**.

**macOS** (`domain-recon-macos-arm64.zip` for Apple Silicon, `…-x86_64.zip` for Intel):
1. Unzip and move `domain-recon.app` to `/Applications`.
2. The build is unsigned, so the first launch needs **right-click → Open** (then confirm). After that a
   double-click works. (Alternatively: `xattr -dr com.apple.quarantine /Applications/domain-recon.app`.)

**Windows** (`domain-recon-windows-x64.zip`):
1. Unzip anywhere and run `domain-recon.exe` from the extracted folder.
2. The build is unsigned, so SmartScreen may warn — choose **More info → Run anyway**.

Data is stored per-user (macOS: `~/Library/Application Support/domain-recon`,
Windows: `%APPDATA%\domain-recon`).

## Run from source

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python -m app.desktop          # local desktop mode (opens a browser)
# or the bare web server:
.venv/bin/uvicorn app.main:app --port 8795
```

Build a standalone app yourself (macOS / Windows / Linux):

```bash
./build.sh        # result in dist/ (domain-recon.app on macOS, domain-recon/ elsewhere)
```

## Command line (no web server)

```bash
python -m app.cli scan example.com                    # passive only
python -m app.cli scan example.com --active           # passive + active (port scan, fingerprint)
python -m app.cli scan example.com --active --ports full --intensity normal --brute --json
```

## Environment variables

| Variable | Description |
|---|---|
| `RECON_DATA` | data directory (SQLite); default `./data` |
| `RECON_ALLOWED_HOSTS` | allowed `Host` headers (comma-separated); empty = no filtering |
| `RECON_MAX_CONCURRENCY` | max concurrent scans (default 2) |
| `RECON_MAX_HOSTS` | cap on hosts processed per scan (default 750) |
| `RECON_MAX_SOCKETS` | global cap on concurrent TCP connections (default 512) |
| `RECON_KEEP` | number of scans retained (default 60) |
| `RECON_PROXY_SECRET` | if set, only requests carrying the matching `X-Recon-Proxy` header are served |
| `DNS_RESOLVERS` | resolvers for DNS checks (default `1.1.1.1,8.8.8.8`) |

## HTTP API

- `POST /api/scan` — start a passive scan `{domain}` → `{id}`
- `POST /api/scan/{id}/active` — start the active phase `{ports, custom_ports, intensity, brute, allow_private}`
- `GET /api/scan/{id}/seo/candidates` — ranked SEO candidates + exclusions (no network requests)
- `POST /api/scan/{id}/seo` — SEO / AI visibility audit `{full: [url…], quick: [url…]}` (max 10 full, 30 quick)
- `GET /api/scan/{id}` — status + results (for polling)
- `GET /api/scans` — recent scans · `GET /api/version`
- `POST /api/scan/{id}/cancel` · `DELETE /api/scan/{id}`
- `GET /api/export/{id}.csv` · `GET /api/export/{id}.json`
- `GET /graph` — relationship graph · `GET /healthz`

## Security

No built-in authentication — when hosting the web UI, put it behind a reverse proxy with authentication.
Strict CSP, `noindex`, request-body limit, `Host` allow-list and domain validation. The desktop app binds
to `127.0.0.1` only. A short self-assessment of the tool's own attack surface is in [AUDIT.md](AUDIT.md).
The TCP-connect port scan needs no elevated privileges.

---
sadrobot · domain-recon
