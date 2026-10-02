// domain-recon – felületi szövegek: magyar, angol. Csak saját, statikus szövegek.
"use strict";
const I18N = {
  hu: {
    locale: "hu-HU", title: "domain-recon · sadrobot",
    eyebrow: "Domain-feltérképezés · külső nézőpont",
    h1: "Domain-recon",
    lead: "Írj be egy domaint — a passzív fázis felsorolja az aldoméneket, feloldja a hostokat és feltérképezi a DNS-t/ASN-t; az aktív fázist külön kell indítani (portscan, ujjlenyomat).",
    authz: "Csak olyan célpontot vizsgálj, amelyhez van engedélyed. Az aktív fázis (portscan stb.) a célponton látható művelet.",
    ph_domain: "pl. example.com",
    go: "Passzív feltérképezés", newscan: "Új vizsgálat", cancel: "Megszakítás",
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
    active_go: "Aktív vizsgálat indítása", active_running: "Aktív vizsgálat fut…", active_done: "Aktív vizsgálat kész",
    o_ports: "Portok", o_intensity: "Intenzitás", o_extra: "Egyéb",
    p_service: "Szolgáltatás", p_common: "Gyakori (~1100)", p_full: "Teljes (1–65535)", p_custom: "Egyedi",
    ph_custom: "22,80,443,8000-8100",
    i_polite: "Kíméletes", i_normal: "Normál", i_aggressive: "Agresszív",
    x_brute: "DNS-brute (prefix-szótár)", x_private: "Privát IP is",
    // lista
    f_all: "Mind", f_live: "Élő", f_exposed: "Kitett", f_takeover: "Takeover", f_dead: "Nem élő",
    filter_ph: "Szűrés hostnévre / IP-re / ASN-re / szolgáltatásra…",
    col_graph: "Gráf", col_graph: "Graph", col_export_json: "JSON", col_export_csv: "CSV",
    none: "Nincs találat.", no_hosts: "Nincs host.",
    d_ips: "IP-címek", d_cname: "CNAME", d_source: "Forrás", d_ports: "Nyitott portok", d_sans: "TLS SAN (új nevek)",
    d_tech: "Technológia", d_exposed: "Kitett szolgáltatás", d_takeover: "Lehetséges takeover", d_vuln: "Kitettség / sebezhetőség",
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
    lead: "Enter a domain — the passive phase enumerates subdomains, resolves hosts and maps DNS/ASN; the active phase (port scan, fingerprinting) is started separately.",
    authz: "Only scan targets you are authorised to. The active phase (port scan etc.) is visible on the target.",
    ph_domain: "e.g. example.com",
    go: "Passive scan", newscan: "New scan", cancel: "Cancel",
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
    active_go: "Start active scan", active_running: "Active scan running…", active_done: "Active scan done",
    o_ports: "Ports", o_intensity: "Intensity", o_extra: "Extra",
    p_service: "Service", p_common: "Common (~1100)", p_full: "Full (1–65535)", p_custom: "Custom",
    ph_custom: "22,80,443,8000-8100",
    i_polite: "Polite", i_normal: "Normal", i_aggressive: "Aggressive",
    x_brute: "DNS brute (prefix wordlist)", x_private: "Include private IPs",
    f_all: "All", f_live: "Live", f_exposed: "Exposed", f_takeover: "Takeover", f_dead: "Dead",
    filter_ph: "Filter by host / IP / ASN / service…",
    col_export_json: "JSON", col_export_csv: "CSV",
    none: "No matches.", no_hosts: "No hosts.",
    d_ips: "IP addresses", d_cname: "CNAME", d_source: "Source", d_ports: "Open ports", d_sans: "TLS SAN (new names)",
    d_tech: "Technology", d_exposed: "Exposed service", d_takeover: "Possible takeover", d_vuln: "Exposure / vulnerability",
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
