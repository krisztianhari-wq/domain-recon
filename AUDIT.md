# Security self-assessment — domain-recon

**Scope:** the tool's own attack surface — the FastAPI app, the scan engine, the port/service
catalogue, the request handling and the output/export paths. **Method:** code review (threat model:
an authenticated but boundary-pushing user; a malicious *scanned* target; a compromised container;
resource abuse against the host it runs on), `pip-audit`, `bandit`, and local attack probes (stored
XSS via banners/HTML titles, CSV formula injection, SSRF / cloud-metadata, ReDoS, large/slow responses).

> This is by nature an **active reconnaissance** tool (subdomain enumeration, DNS, port scanning). The
> goal here is not to neuter reconnaissance, but to make sure the tool **cannot be turned against the
> operator or the host it runs on**, and that only an authorised operator can drive it against a target.

## Summary
No critical or high open issues. Five issues were fixed, and the surface is defended in depth
(authentication at the proxy + a dedicated network + an optional proxy secret). Three residual risks are
conscious, documented choices.

## Fixed before release
| # | Severity | Issue | Fix |
|---|---|---|---|
| 1 | Medium | **CSV formula injection**: scanned servers' banners/HTML titles are attacker-controlled; a cell starting with `=`/`+`/`-`/`@` would execute as a formula in a spreadsheet. | `_csv_safe()` prefixes any dangerous cell with an apostrophe. |
| 2 | Medium | **SSRF escalation with `allow_private`**: enabling private IPs would also allow scanning loopback and **link-local / cloud-metadata `169.254.169.254`**. | `scannable()` never allows loopback/link-local/unspecified/reserved/multicast (even with `allow_private`); RFC1918 only with explicit opt-in; global always. |
| 3 | Medium | **Host-resource exhaustion**: a large domain's CT history can yield thousands of hosts; a `full` + `aggressive` scan could exhaust file descriptors / memory / CPU. | host cap (`RECON_MAX_HOSTS`, default 750) + a **global socket semaphore** (`RECON_MAX_SOCKETS`, default 512) bounding all concurrent TCP connections; concurrent-scan cap (`RECON_MAX_CONCURRENCY`, default 2). |
| 4 | Low | **ReDoS** on the domain regex for a long, dot-less input. | input is truncated to 253 chars before matching; request body capped at 4 KB. |
| 5 | Low | **Dynamic SQL** column names in `set_status`. | column-name **allow-list**; values were already parameterised. |

## Defence in depth (when hosted)
- **Authentication:** the web UI is meant to sit behind a reverse proxy that enforces authentication; the
  app ships with no built-in auth and should not be exposed directly.
- **Isolation:** run it on a network where only the proxy can reach it; do not publish the container port.
- **Proxy secret (optional):** if `RECON_PROXY_SECRET` is set, the app only accepts requests carrying the
  matching `X-Recon-Proxy` header (constant-time compare); `/healthz` is exempt. This blocks direct access
  even if the proxy is bypassed.

## Reviewed, no issue
- **Stored XSS (from scanned content):** a malicious server's HTML `<title>`, `Server` header, SSH/SMTP
  banner and TLS CN/SAN are all attacker-controlled. Every such value is HTML-escaped client-side, and the
  strict **CSP (`script-src 'self'`)** would stop any injected script even if a value slipped through. The
  `style-src` relaxation (`'unsafe-inline'`, for dynamic bars) grants no script execution.
- **Outbound SSRF beyond scanning:** the app's own outbound calls go to fixed, trusted endpoints (the
  CT/passive-DNS sources and DNS resolvers); user input only selects the *scan target*, which `scannable()`
  filters.
- **DNS parsing:** the custom UDP DNS client bounds name-compression depth against loops; malformed replies
  are swallowed per resolver.
- **SQL injection:** all queries are parameterised; `bandit`'s B608 note on the `set_status` f-string is
  provably harmless given the column allow-list (no user input in column names).
- **Methods / Host:** only GET/HEAD/POST/DELETE routes exist; `RECON_ALLOWED_HOSTS` filters the `Host`
  header; `/openapi.json`, docs and redoc are disabled.
- **Response-side resource use:** banner reads capped at 512 B, HTTP fingerprint at 64 KB, with short
  timeouts; each IP is scanned **once** (even when many subdomains share it).
- **Dependencies:** `pip-audit` — no known vulnerabilities in the pinned versions (fastapi, starlette,
  uvicorn, httpx, …). **bandit:** 0 high; 1 medium (B608, handled above); the lows are robustness
  `try/except` blocks in network parsing and non-crypto `random` use.
- **Container:** pinned `python:3.12-slim` base, non-root uid, nologin shell; pip removed after build;
  read-only app tree; `cap_drop: [ALL]`; the TCP-connect port scan needs **no** `NET_RAW`; data directory
  `0700`; no published port and no Docker socket mounted.

## Residual risks — conscious choices
| # | Severity | Risk | Note |
|---|---|---|---|
| A | Medium | **The host as a vantage point**: every scan's source IP is the host's. An aggressive/full scan is visible on the target and can affect the host IP's reputation. | Default is `polite`; authorisation is the operator's responsibility (surfaced in the UI/README/LICENSE). |
| B | Low | **Internal recon with `allow_private`**: when enabled, the scanner can map the host's own exposed ports. | Off by default; loopback/metadata always excluded. Acceptable for a single-user, authenticated tool. |
| C | Low | **Data retention**: results (hostnames, IPs, banners) are kept for a bounded number of scans in the data directory. | `0700` permissions; shorter retention or an encrypted volume on request. |

---
sadrobot · domain-recon · security self-assessment
