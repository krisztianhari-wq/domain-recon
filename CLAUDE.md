# domain-recon – fejlesztői jegyzet

Domain-feltérképező: aldomének (CT + passzív források) → DNS → (aktív) portscan, ujjlenyomat, kitettség, PQ-TLS; lista, gráf, exportok. Felhasználói leírás (angol): README.md; biztonsági audit: AUDIT.md. Üzemeltetési részletek: CLAUDE.local.md (nincs gitben).

**Ez a repó PUBLIKUS.** Ide és a README/AUDIT-ba nem kerülhet szerver-IP, saját hosztnév/infra-részlet, személyes név/e-mail, belső céges információ vagy konkrét (harmadik fél) célpont. A README és az AUDIT angol, infra-információ nélkül.

## Indítás és teszt
- Venv: `/opt/homebrew/bin/python3.14 -m venv .venv && .venv/bin/pip install -r requirements.txt` (a rögzített FastAPI/uvicorn 3.10+ kell, a rendszer-python 3.9 nem jó).
- Launch config `domain-recon` (projekt `.claude/launch.json` és a közös `~/Claude_code/.claude/launch.json`) → 127.0.0.1:8795.
- CLI: `.venv/bin/python -m app.cli scan <domain> [--active] [--ports service|common|full|custom --custom 22,80,8000-8100] [--intensity polite|normal|aggressive] [--brute] [--no-ports] [--private] [--json]` (alapból csak passzív).
- Teszt: nincs unit-teszt; a CI `check` jobja: `python -m compileall -q app`, import-smoke (`app.main, app.engine, …`), `python -m app.cli scan --help`. Helyben ugyanezt futtasd.
- Függőségek rögzítve; `pip-audit -r requirements.txt` (tiszta), bandit magas 0.

## Felépítés
- `app/engine.py` Engine: enumerate → resolve → scan, intenzitás-profilok, megszakítás. `sources.py` certspotter/crt.sh/anubis/wayback/hackertarget; `enrich.py` PTR + ASN/ország/org (Team Cymru DNS); `ports.py` (service / common ≈1075 / full 65535 / custom); `fingerprint.py` HTTP/TLS/banner + tech; `vulncheck.py` GET-only kitettség (.git/.env/dir-listing/ES/Kibana/actuator…); `pqscan.py` poszt-kvantum TLS; `netchecks.py` DNS/TCP (a saját uptime-monitorból másolva); `db.py` SQLite WAL (`_migrate()` ALTER-rel pótolja a hiányzó oszlopokat); `report.py` MD/JSON/CSV, `xlsx.py`; `main.py` API; `desktop.py` + `launcher.py` asztali indító.
- Háromfázisú, mindegyik külön indítható: PASSZÍV az alap (wildcard-felismerés, DNS-posture MX/NS/CAA/SPF/DMARC/DKIM, takeover-heurisztika); AKTÍV `POST /api/scan/{id}/active` (portscan, ujjlenyomat, PQ-TLS, kitettség); **CVE** `POST /api/scan/{id}/cve` — önálló, könnyű HTTP-fejléc-lekérés az élő hostokon → termék+verzió → ismert kritikus CVE (`vulncheck.php_cve_findings`, jelenleg php2shell CVE-2026-109618/109619, verzió alapján, nem kihasználás). Gráf: `/graph` (SVG domain↔host↔IP↔ASN).
- `static/`: sadrobot UI, HU/EN (`i18n.js`, hover-magyarázatok EXPLAIN), `theme.js`; index/graph HTML `no-cache`.
- „Jelentés" = `/report?id=` (`report.py build_html` + `report.css` A4). **PDF: egykattintásos szerveroldali letöltés** (`/api/export/{id}.pdf?lang=&focus=&cve=`, `report.py build_pdf`, reportlab) — nem a böngésző nyomtatásán múlik (a korábbi „üres PDF" ezzel megszűnt); a „Nyomtatás" gomb is megmarad. A Markdown az `/api/export/{id}.md`-n. Riport kétnyelvű (`?lang=hu|en`) és választható tartalmú (`?focus=full|cve` + `?cve=php|apache|confluence`). Statisztika-csempék kattinthatók (szűrés), CVE-badge a hostsorban.
- **Kétnyelvű találatok:** a CVE- (`cvescan.py`) és kitettség- (`vulncheck.exposed_checks`) findingök `title`/`evidence` (HU) **és** `title_en`/`evidence_en` (EN) mezőt is hordoznak; a riport/UI a nyelvhez illőt mutatja (`report._fl`, `app.js fl()`). Régi (egynyelvű) findingök HU-ra esnek vissza → újraszkennelés kell az EN szöveghez.
- **CVE-motor** (`app/cvescan.py`, a CVE-fázis hívja): minden találat `method` mezővel, **külön reportolva**. **A) version** (Server/X-Powered-By): PHP php2shell (CVE-2026-109618/109619), PHP-CGI CVE-2024-4577 (Windows+CGI), Apache CVE-2021-41773/42013 (2.4.49/2.4.50), CVE-2021-40438 (≤2.4.48). **B) fingerprint** (kíméletes GET): Confluence verzió → CVE-2022-26134/22515. Verzió-alapú, NEM kihasználás. UI/PDF/MD két szekció; JSON `known_cves.by_version|by_fingerprint`. Appliance-ujjlenyomatok (Citrix/Ivanti/Fortinet/PAN/MOVEit) külön körben, advisory-ellenőrizve.
- Verzió: `app/__init__.py __version__` (most 0.7.0) + `/api/version` + lábléc; `app/BUILD` a deploy-szkriptből (gitignore). A HTML verziós asset-URL-lel megy (`?v=<verzió>`, a `/` route behelyettesíti a `__VER__`-t) + statikus `no-cache` → nincs beragadt régi app.js.
- Bemenet: `_norm_target` (main.py) felismeri: domain | IP | CIDR | `a-b`/`a.b.c.d-N` tartomány. IP-módban `engine.run_passive_ips()` leltároz (PTR + ASN/ország/org), nincs CT/wildcard/posture/takeover/brute; `opts.target_kind="ip"`, `target_ips` capelve `RECON_MAX_HOSTS`-ra.

## Kiadás
- /release skill: verzióemelés, tag `vX.Y.Z` → `.github/workflows/build.yml` (mac arm64 / mac Intel / Windows x64 PyInstaller zip, GitHub Release, bőbeszédű angol release notes). Alapból patch-bump.
- Helyi build: `./build.sh` (mac `.app`/`.icns`, Win `.exe`/`.ico`, Linux; `build-mac.sh` wrapper) → `dist/`; telepítve `/Applications/domain-recon.app`. `run-mac.command` forrásból indít. Ikon: radar-scope (`assets/icon.svg` → favicon, `icon.icns`, `icon.ico`).

## Döntések
- Csak engedélyezett célpontra (UI/README/LICENSE kiemeli). TCP-connect scan, nincs NET_RAW/ICMP.
- Egy IP-t egyszer szkennel (sok aldomén közös IP-n), de a HTTP-ujjlenyomat hostonként (vhost-aware); a hoston belüli ujjlenyomat korlátozottan párhuzamos (különben a polite túl lassú).
- „Kitett” csak `exposed_flags`/`vuln` alapján (`isExposed()`) – a nyitott 22/SSH önmagában nem kitettség (felhasználói visszajelzés).
- Ha a passzív fázis alig talál (≤1 host vagy 0 élő: wildcard cert / nincs apex A-rekord) → az aktív kártya jelzi és előre bepipálja a DNS-brute-ot (kliensoldali heurisztika).
- PQ-TLS: kézzel épített TLS 1.3 ClientHello üres key_share-rel, hibrid ML-KEM csoportokat kínál; HRR a PQ csoporttal = PQ kulcscsere. Nincs PQC-lib (a pqcheck technikája). Cert: stdlib DER-parse (RSA/ECDSA/EdDSA klasszikus, ML-DSA/SPHINCS+ PQ). MD+JSON exportban is.
- Exportok hostonként tagolva (figyelmet igénylő → élő → nem élő). XLSX: host×port soronként, host-mező minden sorban (a sávozás miatt), HTTP-státusz színkód, fagyasztás+szűrő; de-brandelt paletta (#0E2733 fejléc, #0B8FA0 akcent) – nem céges színek.
- Biztonság (AUDIT.md): CSV-képletinjekció (`_csv_safe`), SSRF (loopback/link-local/169.254 soha), `RECON_MAX_HOSTS=750`, `RECON_MAX_SOCKETS=512`, domain-hosszkorlát (ReDoS), SQL oszlopnév-fehérlista, `RECON_PROXY_SECRET` (`X-Recon-Proxy`) mélységi védelem, `RECON_ALLOWED_HOSTS`. CSP `style-src 'self' 'unsafe-inline'` (dinamikus sávok).

## Buktatók
- `/healthz` minden Host- és proxy-titok-ellenőrzés előtt átmegy, különben a konténer belső healthcheckje (Host: localhost) 400 → unhealthy.
- PQ cert-lekérés: IP-re csatlakozz, de a hostnév legyen az SNI, különben közös IP-s vhostnál üres a cert.
- A `.claude/`, `*.spec`, `build/`, `dist/`, `data/` gitignore-olt.
