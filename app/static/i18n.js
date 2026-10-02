// domain-recon – felületi szövegek: magyar, angol. Csak saját, statikus szövegek.
"use strict";
const I18N = {
  hu: {
    locale: "hu-HU", title: "domain-recon · sadrobot",
    eyebrow: "Domain-feltérképezés · külső nézőpont",
    h1: "Domain-recon",
    lead: "Írj be egy domaint — a felsorolja az aldoméneket, feloldja a hostokat (élő / nem élő), feltérképezi a nyitott portokat és a szolgáltatásokat.",
    authz: "Csak olyan célpontot vizsgálj, amelyhez van engedélyed. A teljes portscan aktív, zajos művelet.",
    ph_domain: "pl. example.com",
    go: "Feltérképezés", cancel: "Megszakítás", newscan: "Új vizsgálat",
    o_ports: "Portok", o_intensity: "Intenzitás", o_extra: "Egyéb",
    p_service: "Szolgáltatás", p_common: "Gyakori (~1100)", p_full: "Teljes (1–65535)", p_custom: "Egyedi",
    ph_custom: "22,80,443,8000-8100",
    i_polite: "Kíméletes", i_normal: "Normál", i_aggressive: "Agresszív",
    x_ct: "CT-napló (aldomének)", x_wordlist: "Prefix-szótár", x_scanports: "Portscan", x_private: "Privát IP is",
    st_queued: "sorban", st_running: "fut", st_done: "kész", st_error: "hiba", st_canceled: "megszakítva",
    stage_enumerate: "aldomének felsorolása", stage_resolve: "DNS-feloldás", stage_scan: "portscan", stage_done: "kész", stage_queued: "indítás",
    m_hosts: "Host", m_live: "Élő", m_exposed: "Kitett", m_ports: "Nyitott port",
    f_all: "Mind", f_live: "Élő", f_exposed: "Kitett", f_dead: "Nem élő",
    filter_ph: "Szűrés hostnévre / IP-re / szolgáltatásra…",
    col_export_json: "JSON", col_export_csv: "CSV",
    none: "Nincs találat.", no_hosts: "Nincs host.",
    d_ips: "IP-címek", d_cname: "CNAME", d_source: "Forrás", d_ports: "Nyitott portok", d_sans: "TLS SAN (új nevek)",
    t_port: "Port", t_svc: "Szolgáltatás", t_detail: "Részlet", t_rtt: "RTT",
    live_yes: "élő", live_no: "nem élő", exposed: "kitett",
    hist_title: "Korábbi vizsgálatok", hist_empty: "Még nincs vizsgálat.",
    confirm_del: "Törlöd ezt a vizsgálatot?",
    err_start: "A vizsgálat indítása nem sikerült.", err_load: "Nem elérhető.",
    footer_a: "sadrobot · domain-recon", footer_b: "Csak engedélyezett célpontra",
  },
  en: {
    locale: "en-GB", title: "domain-recon · sadrobot",
    eyebrow: "Domain reconnaissance · external viewpoint",
    h1: "Domain-recon",
    lead: "Enter a domain — it enumerates subdomains, resolves hosts (live / dead), maps open ports and services.",
    authz: "Only scan targets you are authorised to. A full port scan is an active, noisy operation.",
    ph_domain: "e.g. example.com",
    go: "Map it", cancel: "Cancel", newscan: "New scan",
    o_ports: "Ports", o_intensity: "Intensity", o_extra: "Extra",
    p_service: "Service", p_common: "Common (~1100)", p_full: "Full (1–65535)", p_custom: "Custom",
    ph_custom: "22,80,443,8000-8100",
    i_polite: "Polite", i_normal: "Normal", i_aggressive: "Aggressive",
    x_ct: "CT logs (subdomains)", x_wordlist: "Prefix wordlist", x_scanports: "Port scan", x_private: "Include private IPs",
    st_queued: "queued", st_running: "running", st_done: "done", st_error: "error", st_canceled: "canceled",
    stage_enumerate: "enumerating subdomains", stage_resolve: "resolving DNS", stage_scan: "scanning ports", stage_done: "done", stage_queued: "starting",
    m_hosts: "Hosts", m_live: "Live", m_exposed: "Exposed", m_ports: "Open ports",
    f_all: "All", f_live: "Live", f_exposed: "Exposed", f_dead: "Dead",
    filter_ph: "Filter by host / IP / service…",
    col_export_json: "JSON", col_export_csv: "CSV",
    none: "No matches.", no_hosts: "No hosts.",
    d_ips: "IP addresses", d_cname: "CNAME", d_source: "Source", d_ports: "Open ports", d_sans: "TLS SAN (new names)",
    t_port: "Port", t_svc: "Service", t_detail: "Detail", t_rtt: "RTT",
    live_yes: "live", live_no: "dead", exposed: "exposed",
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
