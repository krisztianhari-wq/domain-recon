# domain-recon

Írj be egy domaint — a **domain-recon** felsorolja az aldoméneket, feloldja a hostokat
(élő / nem élő), feltérképezi a nyitott portokat és a szolgáltatásokat, és listát ad róluk.
FastAPI + SQLite, sadrobot-arculatú dashboard, HU/EN, sötét/világos téma.

> ⚠️ **Csak olyan célpontot vizsgálj, amelyhez van engedélyed.** A port-feltérképezés — különösen a
> teljes (1–65535) scan — aktív, a célponton látható művelet. A felelősség a futtatóé.

## Mit csinál

1. **Felsorolás (enumerate)** — aldomének a **certspotter CT-naplóból** (passzív), plusz az apex;
   opcionálisan egy kis **prefix-szótár** (www, api, mail, dev, …) DNS-próbával.
2. **Feloldás (resolve)** — DNS A/AAAA/CNAME; az NXDOMAIN kiesik, az IP-k rögzülnek (élő / nem élő).
3. **Portscan (scan)** — nyitott TCP-portok. Egy IP-t **egyszer** szkennel (kíméletes, akkor is, ha több
   aldomén ugyanarra az IP-re mutat). Profilok: `service` · `common` (~1100) · `full` (1–65535) · `custom`.
4. **Ujjlenyomat** — web-portnál HTTP státusz + `Server` + `<title>`, és a **TLS-tanúsítvány** CN/SAN/lejárat
   (a SAN gyakran új aldomén-neveket is elárul); egyéb portnál passzív **banner** (pl. SSH/SMTP/FTP).

Minden eredmény listázható, szűrhető (host/IP/szolgáltatás), és **CSV/JSON** exportálható.

## Intenzitás

| Fokozat | Port-párhuzam/IP | Host-párhuzam | Port-timeout | Jelleg |
|---|---|---|---|---|
| `polite` (alap) | 12 | 2 | 3,0 s | kíméletes, lassú |
| `normal` | 64 | 4 | 2,0 s | kiegyensúlyozott |
| `aggressive` | 250 | 8 | 1,2 s | gyors, zajos |

Alapból **csak publikus IP-t** szkennel (`allow_private` kapcsolja be a belső tartományokat is).

## Mac-alkalmazás (helyi, telepíthető)

A domain-recon futhat a saját gépeden önálló `.app`-ként — ilyenkor a **te géped a mérőpont**
(nincs megosztott szerver-IP), és az adat a `~/Library/Application Support/domain-recon` mappába kerül.

- **Kész `.app`:** a GitHub **Releases** / **Actions** oldalról (macOS arm64 és Intel). Kibontás után
  első indításkor: jobbklikk → *Megnyitás* (aláíratlan build). Böngészőablakban nyílik meg.
- **Építés helyben:**
  ```bash
  ./build-mac.sh          # eredmény: dist/domain-recon.app
  ```
- **Építés nélkül, dupla kattintással:** a Finderben a **`run-mac.command`** (első indításkor létrehozza a
  virtuális környezetet, majd böngészőt nyit).

## Helyi futtatás (fejlesztői)

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/uvicorn app.main:app --port 8795      # vagy: .venv/bin/python -m app.desktop
```

Parancssorból, webszerver nélkül:

```bash
python -m app.cli scan example.com --ports service --intensity polite
python -m app.cli scan example.com --ports full --intensity normal --json
```

## Környezeti változók

| Változó | Leírás |
|---|---|
| `RECON_DATA` | adatkönyvtár (SQLite); alap: `./data` |
| `RECON_ALLOWED_HOSTS` | engedélyezett `Host`-fejlécek (vesszővel); üres = nincs szűrés |
| `RECON_MAX_CONCURRENCY` | egyidejű vizsgálatok max. száma (alap 2) |
| `RECON_KEEP` | megőrzött vizsgálatok száma (alap 60) |
| `DNS_RESOLVERS` | DNS-ellenőrzésekhez (alap `1.1.1.1,8.8.8.8`) |

## API (olvasó, kivéve a vizsgálat indítását)

- `POST /api/scan` — új vizsgálat `{domain, ports, custom_ports, intensity, ct, wordlist, scan_ports, allow_private}` → `{id}`
- `GET /api/scan/{id}` — állapot + eredmény-hostok (folyamat-lekérdezéshez)
- `GET /api/scans` — korábbi vizsgálatok
- `POST /api/scan/{id}/cancel` · `DELETE /api/scan/{id}`
- `GET /api/export/{id}.csv` · `GET /api/export/{id}.json`
- `GET /healthz`

## Biztonság

Nincs beépített hitelesítés — az élesben fordított proxy (passkey / oauth2-proxy) elé kerül.
Szigorú CSP, `noindex`, kéréstörzs-limit, `TrustedHost`, domain-validáció. A konténer nem root,
csak olvasható fájlrendszerrel és eldobott képességekkel fut (a TCP-connect portscanhez nem kell `NET_RAW`).

sadrobot · PoC
