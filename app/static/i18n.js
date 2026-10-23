// domain-recon – felületi szövegek: magyar, angol. Csak saját, statikus szövegek.
"use strict";
const I18N = {
  hu: {
    locale: "hu-HU", title: "domain-recon · sadrobot",
    eyebrow: "Domain-feltérképezés · külső nézőpont",
    h1: "Domain-recon",
    lead: "Írj be egy domaint, IP-t vagy IP-tartományt (CIDR / a-b). Domainnél a passzív fázis felsorolja az aldoméneket és feltérképezi a DNS-t/ASN-t; IP-tartománynál a címeket leltározza (PTR + ASN). Az aktív fázist (portscan, ujjlenyomat) külön kell indítani.",
    authz: "Csak olyan célpontot vizsgálj, amelyhez van engedélyed. Az aktív fázis (portscan stb.) a célponton látható művelet.",
    ph_domain: "pl. example.com, 203.0.113.0/24 vagy 203.0.113.1-50",
    go: "Passzív feltérképezés", newscan: "Új vizsgálat", cancel: "Megszakítás",
    import_btn: "Domain/IP betöltés (XLS/CSV)", import_loading: "Fájl beolvasása…",
    import_ready: "{what} betöltve ({f}) — indítsd a leltárt (utána CVE / aktív / teljes passzív domainenként).",
    import_dom: "{n} domain", import_ip: "{n} IP",
    import_none: "Nem találtam domaint vagy publikus IP-t a fájlban.",
    import_err: "Nem olvasható fájl — XLSX vagy CSV kell.", import_trunc: "(a felső korlát miatt csak az első néhány száz)",
    d_fullscan: "Teljes passzív",
    phase_passive: "passzív", phase_active: "aktív",
    st_queued: "sorban", st_running: "fut", st_done: "kész", st_error: "hiba", st_canceled: "megszakítva", st_none: "—",
    stage_enumerate: "aldomének (több forrás)", stage_resolve: "DNS-feloldás", stage_enrich: "ASN/PTR gazdagítás",
    stage_posture: "DNS-posture", stage_done: "kész", stage_queued: "indítás",
    stage_scan: "portscan", stage_brute: "DNS-brute",
    m_hosts: "Host", m_live: "Élő", m_takeover: "Takeover?", m_ports: "Nyitott port", m_exposed: "Kitett",
    // posture
    posture_title: "DNS / e-mail posture", p_spf: "SPF", p_dmarc: "DMARC", p_dkim: "DKIM", p_caa: "CAA",
    p_mx: "MX", p_ns: "NS", p_wildcard: "Wildcard DNS", p_present: "van", p_missing: "hiányzik", p_none: "nincs",
    wildcard_warn: "Wildcard DNS aktív ({0}) — a „*.” bármire feloldhat; az ilyen hostok jelölve.",
    // aktív panel
    active_title: "Aktív vizsgálat", active_help: "A felderített hostok megérintése: portscan, HTTP/TLS + technológia-ujjlenyomat, takeover-megerősítés.",
    active_go: "Aktív vizsgálat indítása", active_hint: "A passzív felderítés alig talált hostot — a domain feltehetően wildcard-tanúsítványt használ vagy nincs apex-rekordja. Kapcsold be a DNS-brute-ot (előre bepipálva), hogy a gyakori aldomének (pl. app, api) is előkerüljenek.", active_running: "Aktív vizsgálat fut…", active_done: "Aktív vizsgálat kész",
    o_ports: "Portok", o_intensity: "Intenzitás", o_extra: "Egyéb",
    p_service: "Szolgáltatás", p_common: "Gyakori (~1100)", p_full: "Teljes (1–65535)", p_custom: "Egyedi",
    ph_custom: "22,80,443,8000-8100",
    i_polite: "Kíméletes", i_normal: "Normál", i_aggressive: "Agresszív",
    x_brute: "DNS-brute (prefix-szótár)", x_private: "Privát IP is",
    // lista
    f_all: "Mind", f_live: "Élő", f_exposed: "Kitett", f_cve: "CVE", f_takeover: "Takeover", f_dead: "Nem élő",
    filter_ph: "Szűrés hostnévre / IP-re / ASN-re / szolgáltatásra…",
    col_graph: "Gráf", col_md: "Jelentés", col_xlsx: "XLSX", col_graph: "Graph", col_md: "Report", col_xlsx: "XLSX", col_export_json: "JSON", col_export_csv: "CSV",
    none: "Nincs találat.", no_hosts: "Nincs host.",
    d_ips: "IP-címek", d_cname: "CNAME", d_source: "Forrás", d_ports: "Nyitott portok", d_sans: "TLS SAN (új nevek)",
    d_tech: "Technológia", d_exposed: "Kitett szolgáltatás", d_takeover: "Lehetséges takeover", d_vuln: "Kitettség / sebezhetőség", d_pq: "Kvantum-reziliencia (TLS)", m_pq: "PQ kulcscsere", d_cve: "Ismert sebezhetőség (CVE)", d_cve_ver: "Ismert CVE — verzió alapján", d_cve_fp: "Ismert CVE — ujjlenyomat alapján", m_cve: "CVE-találat",
    cve_title: "Ismert sebezhetőségek (CVE)", cve_help: "Az élő hostok fejlécéből termék+verzió → ismert kritikus CVE (verzió alapján, nem kihasználás).", cve_go: "CVE-vizsgálat indítása", cve_running: "CVE-vizsgálat fut…", cve_done: "CVE-vizsgálat kész", cve_scanning: "CVE / verzió-ellenőrzés",
    cve_info_sum: "Mit néz a vizsgálat?", cve_info_a: "A) Verzió alapján (Server / X-Powered-By fejléc):", cve_info_b: "B) Ujjlenyomat alapján (kíméletes GET):",
    cve_info_php2shell: "PHP php2shell RCE — CVE-2026-109618 / CVE-2026-109619", cve_info_phpcgi: "PHP-CGI argumentuminjekció (RCE) — CVE-2024-4577 (Windows+CGI)", cve_info_apache_pt: "Apache path traversal → RCE — CVE-2021-41773 / CVE-2021-42013 (2.4.49/2.4.50)", cve_info_apache_proxy: "Apache mod_proxy SSRF — CVE-2021-40438 (≤2.4.48)", cve_info_conf_ognl: "Confluence OGNL-injekció (RCE) — CVE-2022-26134", cve_info_conf_bypass: "Confluence jogosultság-megkerülés — CVE-2023-22515",
    sub_title: "Aldomén-felderítés", sub_help: "A betöltött domainekre CT-alapú aldomén-felderítés; az új hostok a leltárhoz adódnak (passzív).",
    sub_go: "Aldomén-felderítés indítása", sub_running: "Aldomén-felderítés fut…", sub_done: "Aldomén-felderítés kész",
    sub_enumerating: "Domainek feldolgozása (CT)", sub_resolving: "Aldomének feloldása",
    t_port: "Port", t_svc: "Szolgáltatás", t_detail: "Részlet", t_rtt: "RTT",
    live_yes: "élő", live_no: "nem élő", exposed: "kitett", wild: "wildcard", confirmed: "megerősítve", suspected: "gyanús",
    hist_title: "Korábbi vizsgálatok", hist_empty: "Még nincs vizsgálat.",
    confirm_del: "Törlöd ezt a vizsgálatot?",
    err_start: "A vizsgálat indítása nem sikerült.", err_load: "Nem elérhető.",
    footer_a: "sadrobot · domain-recon", footer_b: "Csak engedélyezett célpontra",
  },
  en: {
    locale: "en-GB", title: "domain-recon · sadrobot",
    eyebrow: "Domain reconnaissance · external viewpoint",
    h1: "Domain-recon",
    lead: "Enter a domain, IP or IP range (CIDR / a-b). For a domain the passive phase enumerates subdomains and maps DNS/ASN; for an IP range it inventories the addresses (PTR + ASN). The active phase (port scan, fingerprinting) is started separately.",
    authz: "Only scan targets you are authorised to. The active phase (port scan etc.) is visible on the target.",
    ph_domain: "e.g. example.com, 203.0.113.0/24 or 203.0.113.1-50",
    go: "Passive scan", newscan: "New scan", cancel: "Cancel",
    import_btn: "Load domains/IPs (XLS/CSV)", import_loading: "Reading file…",
    import_ready: "{what} loaded ({f}) — start the inventory (then CVE / active / full passive per domain).",
    import_dom: "{n} domains", import_ip: "{n} IPs",
    import_none: "No domains or public IPs found in the file.",
    import_err: "Unreadable file — XLSX or CSV required.", import_trunc: "(capped to the first few hundred)",
    d_fullscan: "Full passive",
    phase_passive: "passive", phase_active: "active",
    st_queued: "queued", st_running: "running", st_done: "done", st_error: "error", st_canceled: "canceled", st_none: "—",
    stage_enumerate: "subdomains (multi-source)", stage_resolve: "DNS resolution", stage_enrich: "ASN/PTR enrichment",
    stage_posture: "DNS posture", stage_done: "done", stage_queued: "starting",
    stage_scan: "port scan", stage_brute: "DNS brute",
    m_hosts: "Hosts", m_live: "Live", m_takeover: "Takeover?", m_ports: "Open ports", m_exposed: "Exposed",
    posture_title: "DNS / email posture", p_spf: "SPF", p_dmarc: "DMARC", p_dkim: "DKIM", p_caa: "CAA",
    p_mx: "MX", p_ns: "NS", p_wildcard: "Wildcard DNS", p_present: "present", p_missing: "missing", p_none: "none",
    wildcard_warn: "Wildcard DNS active ({0}) — “*.” may resolve anything; such hosts are flagged.",
    active_title: "Active scan", active_help: "Touches the discovered hosts: port scan, HTTP/TLS + technology fingerprint, takeover confirmation.",
    active_go: "Start active scan", active_hint: "Passive discovery found almost no hosts — the domain likely uses a wildcard certificate or has no apex record. Enable DNS brute-force (pre-checked) to surface common subdomains (e.g. app, api).", active_running: "Active scan running…", active_done: "Active scan done",
    o_ports: "Ports", o_intensity: "Intensity", o_extra: "Extra",
    p_service: "Service", p_common: "Common (~1100)", p_full: "Full (1–65535)", p_custom: "Custom",
    ph_custom: "22,80,443,8000-8100",
    i_polite: "Polite", i_normal: "Normal", i_aggressive: "Aggressive",
    x_brute: "DNS brute (prefix wordlist)", x_private: "Include private IPs",
    f_all: "All", f_live: "Live", f_exposed: "Exposed", f_cve: "CVE", f_takeover: "Takeover", f_dead: "Dead",
    filter_ph: "Filter by host / IP / ASN / service…",
    col_export_json: "JSON", col_export_csv: "CSV",
    none: "No matches.", no_hosts: "No hosts.",
    d_ips: "IP addresses", d_cname: "CNAME", d_source: "Source", d_ports: "Open ports", d_sans: "TLS SAN (new names)",
    d_tech: "Technology", d_exposed: "Exposed service", d_takeover: "Possible takeover", d_vuln: "Exposure / vulnerability", d_pq: "Quantum resilience (TLS)", m_pq: "PQ key exchange", d_cve: "Known vulnerability (CVE)", d_cve_ver: "Known CVE — by version", d_cve_fp: "Known CVE — by fingerprint", m_cve: "CVE hits",
    cve_title: "Known vulnerabilities (CVE)", cve_help: "From live hosts’ headers: product+version → known critical CVE (version-based, not exploitation).", cve_go: "Start CVE check", cve_running: "CVE check running…", cve_done: "CVE check done", cve_scanning: "CVE / version check",
    cve_info_sum: "What does the check look for?", cve_info_a: "A) By version (Server / X-Powered-By header):", cve_info_b: "B) By fingerprint (gentle GET):",
    cve_info_php2shell: "PHP php2shell RCE — CVE-2026-109618 / CVE-2026-109619", cve_info_phpcgi: "PHP-CGI argument injection (RCE) — CVE-2024-4577 (Windows+CGI)", cve_info_apache_pt: "Apache path traversal → RCE — CVE-2021-41773 / CVE-2021-42013 (2.4.49/2.4.50)", cve_info_apache_proxy: "Apache mod_proxy SSRF — CVE-2021-40438 (≤2.4.48)", cve_info_conf_ognl: "Confluence OGNL injection (RCE) — CVE-2022-26134", cve_info_conf_bypass: "Confluence broken access control — CVE-2023-22515",
    sub_title: "Subdomain discovery", sub_help: "CT-based subdomain discovery for the loaded domains; new hosts are added to the inventory (passive).",
    sub_go: "Start subdomain discovery", sub_running: "Subdomain discovery running…", sub_done: "Subdomain discovery done",
    sub_enumerating: "Processing domains (CT)", sub_resolving: "Resolving subdomains",
    t_port: "Port", t_svc: "Service", t_detail: "Detail", t_rtt: "RTT",
    live_yes: "live", live_no: "dead", exposed: "exposed", wild: "wildcard", confirmed: "confirmed", suspected: "suspected",
    hist_title: "Previous scans", hist_empty: "No scans yet.",
    confirm_del: "Delete this scan?",
    err_start: "Could not start the scan.", err_load: "Unreachable.",
    footer_a: "sadrobot · domain-recon", footer_b: "Authorised targets only",
  },
};

const LANGS = ["hu", "en"];
function pickLang() {
  let s = null;
  try { s = localStorage.getItem("lang"); } catch (e) { /* private */ }
  if (s && LANGS.includes(s)) return s;
  const nav = (navigator.languages || [navigator.language || ""]).map(x => String(x).slice(0, 2).toLowerCase());
  return nav.find(x => LANGS.includes(x)) || "en";
}
let LANG = pickLang();

function t(key, ...args) {
  const s = (I18N[LANG] && I18N[LANG][key]) ?? I18N.hu[key] ?? key;
  return String(s).replace(/\{(\d)\}/g, (_, i) => args[+i] ?? "");
}

function applyStatic() {
  document.documentElement.lang = LANG;
  document.title = t("title");
  document.querySelectorAll("[data-i18n]").forEach(el => { el.textContent = t(el.dataset.i18n); });
  document.querySelectorAll("[data-i18n-ph]").forEach(el => { el.setAttribute("placeholder", t(el.dataset.i18nPh)); });
  document.querySelectorAll("[data-i18n-aria]").forEach(el => { el.setAttribute("aria-label", t(el.dataset.i18nAria)); });
  document.querySelectorAll(".langs button").forEach(b => b.setAttribute("aria-pressed", String(b.dataset.lang === LANG)));
}

function setLang(l) {
  if (!LANGS.includes(l)) return;
  LANG = l;
  try { localStorage.setItem("lang", l); } catch (e) { /* private */ }
  applyStatic();
}

// ---- magyarázatok a hover-infóhoz (port / rekord / jelzés) ----
const EXPLAIN = {
  ports: {
    hu: {
      21: "FTP – fájlátvitel, gyakran titkosítatlan.", 22: "SSH – távoli terminál; erős hitelesítés kell.",
      23: "Telnet – titkosítatlan távoli elérés, kerülendő.", 25: "SMTP – levélküldés a szerverek között.",
      53: "DNS – névfeloldás (TCP: zónaátvitel is lehet).", 80: "HTTP – webkiszolgáló (titkosítatlan).",
      110: "POP3 – levélletöltés.", 143: "IMAP – levélhozzáférés.", 443: "HTTPS – titkosított web.",
      445: "SMB – Windows fájlmegosztás; publikusan veszélyes.", 465: "SMTPS – titkosított levélküldés.",
      587: "Submission – hitelesített levélfeladás.", 993: "IMAPS.", 995: "POP3S.",
      1433: "MSSQL – adatbázis; ne legyen publikus.", 3306: "MySQL – adatbázis; ne legyen publikus.",
      3389: "RDP – távoli asztal; publikusan kockázatos.", 5432: "PostgreSQL – adatbázis; ne legyen publikus.",
      5900: "VNC – távoli képernyő; publikusan kockázatos.", 6379: "Redis – gyakran auth nélkül; kritikus ha kitett.",
      8080: "HTTP-alt – másodlagos webport.", 8443: "HTTPS-alt – másodlagos titkosított web.",
      9200: "Elasticsearch – adat; auth nélkül súlyos szivárgás.", 11211: "Memcached – cache; UDP-amplifikáció.",
      27017: "MongoDB – adatbázis; auth nélkül súlyos.", 2375: "Docker API – titkosítatlan; teljes gazdagép-átvétel.",
    },
    en: {
      21: "FTP – file transfer, often unencrypted.", 22: "SSH – remote shell; needs strong auth.",
      23: "Telnet – unencrypted remote access, avoid.", 25: "SMTP – server-to-server mail.",
      53: "DNS – name resolution (TCP may allow zone transfer).", 80: "HTTP – web server (unencrypted).",
      110: "POP3 – mail retrieval.", 143: "IMAP – mail access.", 443: "HTTPS – encrypted web.",
      445: "SMB – Windows file sharing; dangerous if public.", 465: "SMTPS – encrypted mail send.",
      587: "Submission – authenticated mail send.", 993: "IMAPS.", 995: "POP3S.",
      1433: "MSSQL – database; should not be public.", 3306: "MySQL – database; should not be public.",
      3389: "RDP – remote desktop; risky if public.", 5432: "PostgreSQL – database; should not be public.",
      5900: "VNC – remote screen; risky if public.", 6379: "Redis – often no auth; critical if exposed.",
      8080: "HTTP-alt – secondary web port.", 8443: "HTTPS-alt – secondary encrypted web.",
      9200: "Elasticsearch – data; no auth means leakage.", 11211: "Memcached – cache; UDP amplification.",
      27017: "MongoDB – database; severe if no auth.", 2375: "Docker API – unencrypted; full host takeover.",
    },
  },
  rec: {
    hu: {
      spf: "SPF – mely szerverek küldhetnek levelet a domain nevében (hamisítás ellen).",
      dmarc: "DMARC – mi történjen a hamisított levéllel (karantén/elutasítás) + jelentés.",
      dkim: "DKIM – a levelek kriptográfiai aláírása selectorral.",
      caa: "CAA – mely hitelesítő adhat ki tanúsítványt a domainre.",
      mx: "MX – a domain levelezőszerverei.", ns: "NS – a domain névszerverei.",
      cname: "CNAME – a host egy másik névre mutat (alias).", ptr: "PTR – az IP-hez tartozó visszirányú név.",
      asn: "ASN – az IP-t birtokló hálózat (szolgáltató/szervezet).",
      takeover: "Lógó CNAME egy külső szolgáltatásra, amely átvehető lehet, ha a szolgáltatásnál nincs beállítva.",
      wildcard: "A domain „*.” rekordja bármely aldomént feloldja — a találat lehet, hogy nem valódi host.",
      exposed: "Kockázatos szolgáltatás kívülről elérhető — érdemes tűzfal mögé tenni.",
      cve: "Ismert kritikus CVE a detektált termék/verzió alapján (fejléc). Verzió-alapú jelzés, nem kihasználás — a verzióegyezés nem bizonyít kihasználhatóságot.",
      pq: "A TLS kulcscseréje kvantum-biztos-e. Klasszikus (RSA/ECDHE) esetén a ma lehallgatott forgalom később kvantumgéppel visszafejthető (harvest-now, decrypt-later); a hibrid ML-KEM ez ellen véd.",
    },
    en: {
      spf: "SPF – which servers may send mail for the domain (anti-spoofing).",
      dmarc: "DMARC – what to do with spoofed mail (quarantine/reject) + reporting.",
      dkim: "DKIM – cryptographic signing of mail via a selector.",
      caa: "CAA – which CA may issue certificates for the domain.",
      mx: "MX – the domain's mail servers.", ns: "NS – the domain's name servers.",
      cname: "CNAME – the host points to another name (alias).", ptr: "PTR – reverse name for the IP.",
      asn: "ASN – the network that owns the IP (provider/org).",
      takeover: "Dangling CNAME to an external service that may be claimable if unconfigured there.",
      wildcard: "The domain's “*.” record resolves any subdomain — a hit may not be a real host.",
      exposed: "A risky service is reachable externally — consider putting it behind a firewall.",
      cve: "A known critical CVE based on the detected product/version (from headers). Version-based signal, not exploitation — a version match does not prove exploitability.",
      pq: "Whether the TLS key exchange is quantum-safe. With classical (RSA/ECDHE) traffic captured today can be decrypted later by a quantum computer (harvest-now, decrypt-later); hybrid ML-KEM protects against this.",
    },
  },
};

function explainPort(port, name) {
  const m = EXPLAIN.ports[LANG] || EXPLAIN.ports.hu;
  return m[port] || `${name || "?"} – ${port}/tcp`;
}
function explainRec(key) {
  const m = EXPLAIN.rec[LANG] || EXPLAIN.rec.hu;
  return m[key] || "";
}
