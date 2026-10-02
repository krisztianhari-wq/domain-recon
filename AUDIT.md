# Biztonsági audit – domain-recon (v0.1), 2026-10-02

**Hatókör:** a domain-recon eszköz saját támadási felülete — a FastAPI-app, a vizsgálómotor, a Docker-image,
a compose-szolgáltatás, a Caddy-blokk és a telepítő scriptek a sadrobot OVH VPS-en, **passkey (oauth2-proxy) mögött**.
**Módszer:** kódátnézés (fenyegetésmodell: hitelesített, de a határokat feszegető felhasználó; rosszindulatú
*beszkennelt* célpont; kompromittált konténer; saját infra elleni erőforrás-visszaélés), `pip-audit`, `bandit`,
helyi támadási próbák (XSS a bannerben/HTML-címben, CSV-képletinjekció, SSRF/metaadat, ReDoS, nagy/lassú válasz),
valamint a konfig-patch próbája az **élő** compose/Caddyfile másolatán.

> Ez az eszköz természeténél fogva **aktív felderítő** (aldomén-felsorolás, DNS, portscan). A cél itt nem a felderítés
> „ártalmatlanítása", hanem hogy az eszköz **ne legyen visszaélhető a futtatóval vagy a saját infrával szemben**, és
> csak a hitelesített felhasználó, csak engedélyezett célpontra használhassa.

## Eredmény röviden
Kritikus vagy magas súlyú nyitott hiba nincs. 5 problémát javítottam a telepítés előtt, és a felületet
több rétegben védtem (passkey + dedikált háló + proxy-titok). 3 maradék kockázat tudatos, dokumentált döntés.

## Javított problémák
| # | Súly | Probléma | Javítás | Ellenőrzés |
|---|---|---|---|---|
| 1 | Közepes | **CSV-képletinjekció**: a beszkennelt szerverek bannerei/HTML-címei felhasználható szövegek; `=`/`+`/`-`/`@` kezdetű cella Excelben képletként futna (adatszivárgás, parancs). | `_csv_safe()` minden exportált cellát aposztróffal semlegesít, ha veszélyes karakterrel kezdődik. | `_csv_safe('=cmd')` → `'=cmd` |
| 2 | Közepes | **SSRF-eszkaláció `allow_private` esetén**: a privát IP engedélyezése mellett a loopback és a **link-local / felhő-metaadat `169.254.169.254`** is szkennelhető lett volna. | `scannable()`: loopback/link-local/unspecified/reserved/multicast **soha** (allow_private mellett sem); RFC1918 csak explicit engedéllyel; globális mindig. | `169.254.169.254`, `127.0.0.1`, `::1` → kizárva |
| 3 | Közepes | **Saját infra DoS**: egy nagy domain CT-naplója több ezer hostot adhat; `full`+`aggressive` scan kimerítené a 3,7 GB-os VPS-t (FD, memória, CPU). | host-plafon (`RECON_MAX_HOSTS`, alap 750) + **globális socket-szemafor** (`RECON_MAX_SOCKETS`, alap 512) az összes egyidejű TCP-kapcsolatra; egyidejű vizsgálatok korlátja (`RECON_MAX_CONCURRENCY`, alap 2). | csonkolás a „note" mezőben jelezve |
| 4 | Alacsony | **ReDoS** a domain-regexen hosszú, pontozás nélküli bemenetre. | a bemenet 253 karakterre vágva a minta előtt; a kéréstörzs 4 KB-ra korlátozva. | hosszú bemenet → gyors elutasítás |
| 5 | Alacsony | **Dinamikus SQL** oszlopnevek (`set_status`). | oszlopnév-**fehérlista**; az értékek eddig is paraméterezve (`?`). | ismeretlen oszlop → `ValueError` |

## Többrétegű hozzáférés-védelem (élesben)
- **Passkey:** a `recon.sadrobot.eu` a közös **oauth2-proxy + Pocket ID** mögött (saját `_recon_auth` süti, saját
  `emails-recon.txt` engedélylista) — csak a felvett e-mail-cím(ek) léphetnek be. Jelszó nincs, csak passkey.
- **Dedikált háló:** a konténer a `recon_net` hálózaton van, **kizárólag a Caddy éri el**; publikált port nincs.
- **Proxy-titok (mélységi védelem):** ha `RECON_PROXY_SECRET` be van állítva, az app csak a Caddy által injektált
  `X-Recon-Proxy` fejlécet fogadja el (`hmac.compare_digest`); a `/healthz` kivétel. Így a konténer közvetlenül
  (a proxy megkerülésével) sem hívható.

## További ellenőrzött pontok, hiba nélkül
- **XSS (tárolt, beszkennelt tartalomból):** a rosszindulatú szerver HTML-`<title>`-je, `Server`-fejléce, SSH/SMTP
  bannere és a TLS CN/SAN mind **támadó-vezérelt**. Minden ilyen a kliensen `esc()`-en megy át (`& < > " '`), és a
  **CSP `script-src 'self'`** miatt beágyazott szkript akkor sem futna, ha egy érték átcsúszna. A `style-src` a
  dinamikus sávok miatt `'unsafe-inline'` — ez nem ad szkriptfuttatást.
- **SSRF a vizsgálaton kívül:** az app kimenő kérései a certspotter CT-API és a DNS-resolverek felé mennek (fix,
  megbízható célok); a felhasználói bemenet csak a *vizsgálat* célját adja, amit a `scannable()` szűr.
- **DNS-válasz feldolgozása:** a saját UDP-DNS-parszer név-tömörítésnél mélységkorláttal véd a végtelen hurok ellen;
  a hibás válasz resolverenként `try/except`-tel elnyelve. (A `random` DNS-txid nem kriptográfiai célú — elfogadható.)
- **SQL-injekció:** minden lekérdezés paraméterezett; a `bandit` B608 jelzése a `set_status` f-stringjére a
  fehérlista miatt bizonyítottan ártalmatlan (felhasználói bemenet nincs az oszlopnevekben).
- **Metódus/Host:** nem GET/HEAD/POST/DELETE út nincs; `RECON_ALLOWED_HOSTS` (élesben a hoszt) szűri a `Host`-fejlécet;
  `/openapi.json`, docs, redoc kikapcsolva (404).
- **Erőforrás a válaszoldalon:** a banner-olvasás 512 B, a HTTP-ujjlenyomat 64 KB, rövid időtúllépésekkel; egy IP-t
  **egyszer** szkennel (közös IP-jű aldoméneknél is).
- **Függőségek:** `pip-audit` — nincs ismert sebezhetőség a rögzített verziókban (fastapi 0.142.2, starlette 1.7.0,
  uvicorn 0.54.0, httpx 0.28.1 stb.).
- **bandit:** 0 magas; 1 közepes (B608, fent kezelve); 10 alacsony (7× `try/except/pass` és 1× `continue` a
  hálózati feldolgozás robosztusságához, 2× `random` nem-kripto célra) — egyik sem biztonsági hiba.
- **Konténer:** `python:3.12.14-slim-trixie` rögzített verzió, uid 10008 (nem root), nologin; a pip a build után
  törölve, az `/app` írásvédett; `cap_drop: [ALL]`; a TCP-connect portscanhez **nem kell** `NET_RAW`. A `/data`
  jogosultsága 0700. Nincs publikált port, Docker-socket nincs becsatolva.
- **Telepítés:** a patch-script idempotens, időbélyeges mentést készít az élő compose/Caddyfile-ról, és **csak a saját
  sorait** érinti; a Caddyfile-t `validate`-eli, és `up -d caddy`-t használ (nem `restart`).

## Maradék kockázatok – tudatos döntés
| # | Súly | Kockázat | Javaslat / állapot |
|---|---|---|---|
| A | Közepes | **A VPS mint mérőpont**: minden scan forrás-IP-je `57.131.194.122`. Egy agresszív/teljes scan a célponton látszik, és a sadrobot-IP reputációját terhelheti (panasz, feketelista). | Alap a `polite`; az engedély a futtató felelőssége (UI/README/LICENSE jelzi). Igény esetén külön, eldobható mérőpont-IP. |
| B | Alacsony | **Belső felderítés `allow_private`-tal**: bekapcsolva a konténer a saját `recon_net`-jén kívülre nem lát ugyan, de a VPS publikus IP-jén nyitott portjait feltérképezheti. | Alapból KI; a loopback/metaadat már tiltva. Elfogadható egyszemélyes, hitelesített eszköznél. |
| C | Alacsony | **Adattárolás**: az eredmények (hostnevek, IP-k, bannerek) 60 vizsgálatig megőrződnek a konténer `/data`-jában. | 0700 jogosultság, passkey mögött; igény esetén rövidebb megőrzés vagy titkosított kötet. |

## Telepítés előtti állapot
A fenti 5 javítás a kódban van (`app/main.py`, `app/engine.py`, `app/db.py`), a hozzáférés-védelem a compose/Caddy
patch-ben. `pip-audit` tiszta, `bandit` magas 0. Az eszköz telepíthető a passkey mögé.

sadrobot · domain-recon · biztonsági audit
