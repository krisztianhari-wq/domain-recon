// domain-recon – kliens: passzív + aktív fázis, posture, gazdagítás, hover-infók. Szövegek: i18n.js
"use strict";
const $ = s => document.querySelector(s);
const $$ = s => [...document.querySelectorAll(s)];
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[c]));
const L = () => t("locale");
// Régi (egynyelvű, HU) findingök render-idejű EN-fordítása – ne kelljen újraszkennelni.
const _HU2EN = [
  ["PHP-CGI argumentuminjekció (RCE)", "PHP-CGI argument injection (RCE)"],
  ["Confluence OGNL-injekció (RCE)", "Confluence OGNL injection (RCE)"],
  ["Confluence jogosultság-megkerülés", "Confluence broken access control"],
  ["Atlassian Confluence észlelve", "Atlassian Confluence detected"],
  ["Kitett phpinfo (információszivárgás)", "Exposed phpinfo (information disclosure)"],
  ["Nyílt Elasticsearch (auth nélkül)", "Open Elasticsearch (no auth)"],
  ["Elérhető Grafana bejelentkezés", "Reachable Grafana login"],
  ["Kitett Apache server-status", "Exposed Apache server-status"],
  ["Nyitott könyvtárlistázás", "Open directory listing"],
  ["Kitett Spring actuator", "Exposed Spring actuator"],
  ["Kitett .git könyvtár", "Exposed .git directory"],
  ["Kitett .env fájl", "Exposed .env file"],
  ["Kitett Prometheus", "Exposed Prometheus"],
  ["Elérhető Kibana", "Reachable Kibana"],
  ["verzió nem olvasható ki – ellenőrizd a", "version not readable – check against"],
  ["verzió alapján, alap konfig érintett", "by version, default config affected"],
  ["alap konfig érintett", "default config affected"],
  ["csak Windows+CGI érintett – ellenőrzendő", "Windows+CGI only – verify"],
  ["csak Windows+CGI – ellenőrzendő", "Windows+CGI only – verify"],
  ["Windows+CGI megerősítve", "Windows+CGI confirmed"],
  ["mod_proxy esetén", "mod_proxy only"],
  ["cluster_name jelen van", "cluster_name present"],
  ["javítva:", "fixed:"],
  ["tartalmaz:", "contains:"],
  [" ellen", ""],
];
const toEn = s => { s = s || ""; for (const [hu, en] of _HU2EN) if (s.includes(hu)) s = s.split(hu).join(en); return s; };
// Találat nyelvfüggő mezője (title/evidence): EN-nél a *_en, ha van; különben a HU render-időben EN-re fordítva.
const fl = (v, key) => LANG === "en" ? (v[key + "_en"] || toEn(v[key])) : (v[key] || "");

let current = null, poll = null, hosts = [], scan = {}, liveFilter = "all", bruteSuggested = false;

function segValue(id) { const b = $(`#${id} button.on`); return b ? b.dataset.v : null; }
$$("#ports button, #intensity button, #livefilter button").forEach(b => {
  b.addEventListener("click", () => {
    b.parentElement.querySelectorAll("button").forEach(x => x.classList.remove("on"));
    b.classList.add("on");
    if (b.parentElement.id === "ports") $("#customwrap").classList.toggle("hide", b.dataset.v !== "custom");
    if (b.parentElement.id === "livefilter") { liveFilter = b.dataset.v; renderHosts(); }
  });
});

// ---- passzív indítás ----
async function startScan() {
  const domain = $("#domain").value.trim();
  const useImport = hasImport();
  if (!domain && !useImport) { $("#domain").focus(); return; }
  bruteSuggested = false;
  $("#go").disabled = true;
  const body = useImport
    ? ((importedHosts && importedHosts.length)
        ? {hosts: importedHosts, ips: importedIps || [], source: importedSource}
        : {ips: importedIps, source: importedSource})
    : {domain};
  try {
    const r = await fetch("/api/scan", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body)});
    if (!r.ok) { const e = await r.json().catch(() => ({})); alert(e.detail || t("err_start")); $("#go").disabled = false; return; }
    const s = await r.json();
    clearImport();
    current = s.id;
    try { history.replaceState(null, "", `#${s.id}`); } catch (e) { /* no-op */ }
    $("#results").classList.remove("hide");
    $("#progcard").classList.remove("hide");
    startPoll();
  } catch (e) { alert(t("err_start")); $("#go").disabled = false; }
}

// ---- Domainek / IP-k betöltése XLS/CSV-ből ----
let importedIps = null, importedHosts = null, importedSource = "";
function hasImport() { return (importedHosts && importedHosts.length) || (importedIps && importedIps.length); }
function clearImport() {
  importedIps = null; importedHosts = null; importedSource = "";
  const n = $("#importnote"); if (n) { n.classList.add("hide"); n.classList.remove("warn"); n.textContent = ""; }
}
async function onImportFile(ev) {
  const f = ev.target.files && ev.target.files[0];
  ev.target.value = "";                 // ugyanaz a fájl újra választható legyen
  if (!f) return;
  const note = $("#importnote");
  note.classList.remove("hide", "warn"); note.textContent = t("import_loading");
  try {
    const r = await fetch("/api/import?name=" + encodeURIComponent(f.name), {method: "POST", body: f});
    const j = await r.json().catch(() => ({}));
    if (!r.ok) { note.classList.add("warn"); note.textContent = j.detail || t("import_err"); return; }
    const nd = j.domain_count || 0, ni = j.count || 0;
    if (!nd && !ni) { clearImport(); note.classList.add("warn"); note.textContent = t("import_none"); return; }
    importedHosts = j.domains || []; importedIps = j.ips || []; importedSource = j.source || f.name;
    $("#domain").value = "";
    // „N domain + M IP betöltve (fájl) — indítsd a leltárt." (a nulla tagot elhagyjuk)
    const parts = [];
    if (nd) parts.push(t("import_dom").replace("{n}", nd));
    if (ni) parts.push(t("import_ip").replace("{n}", ni));
    note.textContent = t("import_ready").replace("{what}", parts.join(" + ")).replace("{f}", importedSource)
      + (j.truncated ? " " + t("import_trunc") : "");
  } catch (e) { note.classList.add("warn"); note.textContent = t("import_err"); }
}

// ---- aktív indítás ----
async function startActive() {
  if (!current) return;
  const body = {
    ports: segValue("ports"), custom_ports: $("#customports").value.trim(),
    intensity: segValue("intensity"), brute: $("#brute").checked, allow_private: $("#allowprivate").checked,
  };
  $("#activego").disabled = true;
  try {
    const r = await fetch(`/api/scan/${current}/active`, {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body)});
    if (!r.ok) { const e = await r.json().catch(() => ({})); alert(e.detail || t("err_start")); $("#activego").disabled = false; return; }
    $("#activeprog").classList.remove("hide");
    startPoll();
  } catch (e) { alert(t("err_start")); $("#activego").disabled = false; }
}

async function startCve() {
  if (!current) return;
  $("#cvego").disabled = true;
  try {
    const r = await fetch(`/api/scan/${current}/cve`, {method: "POST"});
    if (!r.ok) { const e = await r.json().catch(() => ({})); alert(e.detail || t("err_start")); $("#cvego").disabled = false; return; }
    $("#cveprog").classList.remove("hide");
    startPoll();
  } catch (e) { alert(t("err_start")); $("#cvego").disabled = false; }
}

async function startSubdomains() {   // domain-leltár: aldomén-felderítés az összes betöltött domainre
  if (!current) return;
  $("#subgo").disabled = true;
  try {
    const r = await fetch(`/api/scan/${current}/subdomains`, {method: "POST"});
    if (!r.ok) { const e = await r.json().catch(() => ({})); alert(e.detail || t("err_start")); $("#subgo").disabled = false; return; }
    $("#subprog").classList.remove("hide");
    startPoll();
  } catch (e) { alert(t("err_start")); $("#subgo").disabled = false; }
}

function startPoll() { stopPoll(); tick(); poll = setInterval(tick, 1500); }
function stopPoll() { if (poll) { clearInterval(poll); poll = null; } }

async function tick() {
  if (!current) return;
  let s;
  try { s = await (await fetch(`/api/scan/${current}`, {cache: "no-store"})).json(); }
  catch (e) { return; }
  scan = s; hosts = s.hosts || [];
  renderProgress(s); renderActive(s); renderCve(s); renderSubdomains(s); renderStats(); renderPosture(s); renderHosts();
  $("#md").href = `/report?id=${current}&lang=${LANG}`;   // nyomtatható PDF-jelentés (a UI nyelvén)
  $("#md").target = "_blank";
  $("#xlsx").href = `/api/export/${current}.xlsx`;
  $("#csv").href = `/api/export/${current}.csv`;
  $("#json").href = `/api/export/${current}.json`;
  $("#graphlink").href = `/graph#${current}`;
  const passiveDone = ["done", "error", "canceled"].includes(s.status);
  const activeIdle = !["queued", "running"].includes(s.active_status);
  const cveIdle = !["queued", "running"].includes(s.cve_status);
  const subIdle = !["queued", "running"].includes(s.sub_status);
  if (passiveDone && activeIdle && cveIdle && subIdle) { stopPoll(); $("#go").disabled = false; $("#activego").disabled = false; $("#cvego").disabled = false; $("#subgo").disabled = false; loadHistory(); }
}

function renderCve(s) {
  const passiveDone = ["done", "error", "canceled"].includes(s.status);
  $("#cvecard").classList.toggle("hide", !passiveDone || s.status === "error");
  const running = ["queued", "running"].includes(s.cve_status);
  $("#cvego").disabled = running;
  $("#cvego").textContent = running ? t("cve_running") : (s.cve_status === "done" ? t("cve_done") + " · " + t("cve_go") : t("cve_go"));
  $("#cveprog").classList.toggle("hide", !running);
  if (running) {
    const fill = $("#cprogbar").querySelector("i");
    const pct = s.cve_total ? Math.round(s.cve_done / s.cve_total * 100) : 0;
    fill.style.width = pct + "%";
    $("#cstage").textContent = t("cve_scanning");
    $("#cprogtxt").textContent = `${s.cve_done || 0} / ${s.cve_total || 0}`;
  }
}

function renderSubdomains(s) {   // csak domain-leltárnál (hostlist) látható, a passzív után
  const isHostlist = s.opts && s.opts.target_kind === "hostlist";
  const passiveDone = ["done", "error", "canceled"].includes(s.status);
  $("#subcard").classList.toggle("hide", !isHostlist || !passiveDone || s.status === "error");
  const running = ["queued", "running"].includes(s.sub_status);
  $("#subgo").disabled = running;
  $("#subgo").textContent = running ? t("sub_running") : (s.sub_status === "done" ? t("sub_done") + " · " + t("sub_go") : t("sub_go"));
  $("#subprog").classList.toggle("hide", !running);
  if (running) {
    const fill = $("#sprogbar").querySelector("i");
    const indet = s.sub_stage === "enumerate" || !s.sub_total;
    $("#sprogbar").classList.toggle("indet", indet);
    const pct = s.sub_total ? Math.round(s.sub_done / s.sub_total * 100) : 0;
    fill.style.width = indet ? "35%" : pct + "%";
    $("#sstage").textContent = t(s.sub_stage === "resolve" ? "sub_resolving" : "sub_enumerating");
    $("#sprogtxt").textContent = `${s.sub_done || 0} / ${s.sub_total || 0}`;
  }
}

function renderProgress(s) {
  const running = ["queued", "running"].includes(s.status);
  $("#progcard").classList.toggle("hide", !running && s.status !== "error");
  const stageKey = "stage_" + (s.stage || "queued");
  $("#stage").textContent = running ? t(stageKey) : t("st_" + s.status);
  const bar = $("#progbar"), fill = bar.querySelector("i");
  const indet = running && (!s.total || s.stage === "enumerate");
  bar.classList.toggle("indet", indet);
  if (indet) { fill.style.width = "35%"; $("#progtxt").textContent = t(stageKey); }
  else { const pct = s.total ? Math.round(s.done / s.total * 100) : (s.status === "done" ? 100 : 0); fill.style.width = pct + "%"; $("#progtxt").textContent = `${s.done || 0} / ${s.total || 0}`; }
  $("#scanmeta").textContent = esc(s.domain || "") + (s.note ? " · " + s.note : "");
  $("#cancel").classList.toggle("hide", !running);
  if (s.status === "error" && s.error) $("#scanmeta").textContent = s.error;
}

function renderActive(s) {
  const passiveDone = ["done", "error", "canceled"].includes(s.status);
  $("#activecard").classList.toggle("hide", !passiveDone || s.status === "error");
  // jelzés: ha a passzív csak az apexet találta / semmi sem él → DNS-brute kell (wildcard cert / nincs apex-rekord)
  const hint = $("#activehint");
  const notRun = !["queued", "running", "done"].includes(s.active_status);
  const liveCount = hosts.filter(h => h.alive).length;
  const sparse = hosts.length <= 1 || liveCount === 0;
  const isIp = s.opts && s.opts.target_kind === "ip";   // IP-célpontnál a DNS-brute értelmetlen
  const showHint = passiveDone && s.status === "done" && notRun && sparse && !isIp;
  if (hint) {
    hint.classList.toggle("hide", !showHint);
    if (showHint) {
      hint.textContent = t("active_hint");
      if (!bruteSuggested) { $("#brute").checked = true; bruteSuggested = true; }   // egyszer bepipáljuk
    }
  }
  const running = ["queued", "running"].includes(s.active_status);
  $("#activego").disabled = running;
  $("#activego").textContent = running ? t("active_running") : (s.active_status === "done" ? t("active_done") + " · " + t("active_go") : t("active_go"));
  $("#activeprog").classList.toggle("hide", !running);
  if (running) {
    const stageKey = "stage_" + (s.active_stage || "scan");
    $("#astage").textContent = t(stageKey);
    const fill = $("#aprogbar").querySelector("i");
    const pct = s.active_total ? Math.round(s.active_done / s.active_total * 100) : 0;
    fill.style.width = pct + "%";
    $("#aprogtxt").textContent = `${s.active_done || 0} / ${s.active_total || 0}`;
  }
}

// „kitett” = valóban kockázatos szolgáltatás (DB/admin/nyílt adattár) vagy sebezhetőség-találat.
// Egy sima nyitott port (pl. 22/SSH, 25/SMTP) önmagában NEM tesz egy hostot kitetté.
function isExposed(h) { return !!((h.exposed_flags && h.exposed_flags.length) || (h.vuln && h.vuln.length) || (h.cve && h.cve.length)); }
function hasTakeover(h) { return h.takeover && h.takeover.service; }

function renderStats() {
  const live = hosts.filter(h => h.alive).length;
  const tk = hosts.filter(hasTakeover).length;
  const openPorts = hosts.reduce((a, h) => a + (h.ports || []).length, 0);
  const exposed = hosts.filter(isExposed).length;
  const pqAssessed = hosts.filter(h => h.pq && h.pq.kex);
  const pqSafe = pqAssessed.filter(h => h.pq.kex.status === "pq").length;
  $("#stats").classList.remove("hide");
  let html = `
    <div class="stat accent" data-f="all"><b>${t("m_hosts")}</b><span>${hosts.length}</span></div>
    <div class="stat good" data-f="live"><b>${t("m_live")}</b><span>${live}</span></div>
    <div class="stat ${tk ? "bad" : ""}" data-f="takeover" data-tip="${esc(explainRec("takeover"))}"><b>${t("m_takeover")}</b><span>${tk}</span></div>
    <div class="stat ${exposed ? "warn" : ""}" data-f="exposed"><b>${t("m_exposed")}</b><span>${exposed}</span></div>
    <div class="stat" data-f="ports"><b>${t("m_ports")}</b><span>${openPorts}</span></div>`;
  if (pqAssessed.length) {
    const cls = pqSafe === pqAssessed.length ? "good" : pqSafe ? "warn" : "bad";
    html += `<div class="stat ${cls}" data-f="pq" data-tip="${esc(explainRec("pq"))}"><b>${t("m_pq")}</b><span>${pqSafe}/${pqAssessed.length}</span></div>`;
  }
  const cveHosts = hosts.filter(h => h.cve && h.cve.length).length;
  if (cveHosts) html += `<div class="stat bad" data-f="cve" data-tip="${esc(explainRec("cve"))}"><b>${t("m_cve")}</b><span>${cveHosts}</span></div>`;
  $("#stats").innerHTML = html;
}

// csempe → szűrő
function setFilter(f) {
  liveFilter = f;
  document.querySelectorAll("#livefilter button").forEach(x => x.classList.toggle("on", x.dataset.v === f));
  renderHosts();
  $("#results").scrollIntoView({behavior: "smooth", block: "start"});
}
$("#stats").addEventListener("click", e => {
  const tile = e.target.closest(".stat[data-f]");
  if (tile) setFilter(tile.dataset.f);
});

function postCell(key, present, value) {
  const cls = present ? "good" : "warn";
  const state = present ? t("p_present") : t("p_missing");
  return `<div class="postcell ${cls}" data-tip="${esc(explainRec(key))}"><b>${t("p_" + key)}</b><span>${value || state}</span></div>`;
}

function renderPosture(s) {
  const p = s.posture;
  if (!p) { $("#posture").classList.add("hide"); return; }
  $("#posture").classList.remove("hide");
  const cells = [
    postCell("spf", !!p.spf_ok), postCell("dmarc", !!p.dmarc_ok),
    postCell("dkim", (p.dkim || []).length > 0, (p.dkim || []).join(", ")),
    postCell("caa", (p.caa || []).length > 0),
    postCell("mx", (p.mx || []).length > 0, (p.mx || []).length ? (p.mx.length + "×") : ""),
    postCell("ns", (p.ns || []).length > 0, (p.ns || []).length ? (p.ns.length + "×") : ""),
  ].join("");
  $("#postgrid").innerHTML = cells;
  const wc = s.wildcard || [];
  const note = $("#wildcardnote");
  note.textContent = wc.length ? t("wildcard_warn", wc.join(", ")) : "";
  note.classList.toggle("hide", !wc.length);
}

function matchFilter(h, q) {
  if (!q) return true;
  const asn = (h.ips_info || []).map(i => (i.asn || "") + " " + (i.org || "") + " " + (i.ptr || "")).join(" ");
  const hay = [h.host, (h.ips || []).join(" "), h.cname || "", asn,
               (h.ports || []).map(p => p.port + " " + (p.name || "")).join(" "), (h.tech || []).join(" ")].join(" ").toLowerCase();
  return hay.includes(q);
}

function hostClass(h) {
  if (hasTakeover(h)) return "takeover";
  if (!h.alive) return "dead";
  if (isExposed(h)) return "exposed";
  return "live";
}

function renderHosts() {
  const q = ($("#filter").value || "").trim().toLowerCase();
  let list = hosts.filter(h => matchFilter(h, q));
  if (liveFilter === "live") list = list.filter(h => h.alive);
  else if (liveFilter === "dead") list = list.filter(h => !h.alive);
  else if (liveFilter === "exposed") list = list.filter(isExposed);
  else if (liveFilter === "takeover") list = list.filter(hasTakeover);
  else if (liveFilter === "cve") list = list.filter(h => h.cve && h.cve.length);
  else if (liveFilter === "ports") list = list.filter(h => (h.ports || []).length);
  else if (liveFilter === "pq") list = list.filter(h => h.pq && h.pq.kex);
  const rank = h => hasTakeover(h) ? 0 : isExposed(h) ? 1 : h.alive ? 2 : 3;
  list.sort((a, b) => rank(a) - rank(b) || a.host.localeCompare(b.host));
  const box = $("#hostlist");
  if (!list.length) { box.innerHTML = `<p class="empty" style="padding:14px">${hosts.length ? t("none") : t("no_hosts")}</p>`; return; }
  box.innerHTML = list.map(renderHostRow).join("");
}

function ipShort(h) {
  const info = (h.ips_info || [])[0];
  if (!info && (h.ips || []).length) return esc(h.ips[0]);
  if (!info) return "—";
  let s = esc(info.ip);
  if (info.asn) s += ` <span class="asn" data-tip="${esc(explainRec("asn"))}">AS${esc(info.asn)}${info.cc ? " " + esc(info.cc) : ""}</span>`;
  return s;
}

const SEVCLS = {critical: "bad", high: "bad", medium: "warn", low: "warn", info: ""};
function worstVuln(h) {
  const order = ["critical", "high", "medium", "low", "info"];
  const v = h.vuln || [];
  for (const s of order) if (v.some(x => x.severity === s)) return s;
  return null;
}
function badges(h) {
  let b = "";
  if (hasTakeover(h)) { const st = h.takeover.confirmed ? t("confirmed") : t("suspected"); b += `<span class="bdg bad" data-tip="${esc(explainRec("takeover"))}">takeover: ${esc(h.takeover.service)} (${st})</span>`; }
  (h.cve || []).forEach(v => { const c = v.cve && v.cve !== "—" ? " (" + esc(v.cve) + ")" : ""; b += `<span class="bdg ${SEVCLS[v.severity] || "bad"}" data-tip="${esc(fl(v, "evidence") || fl(v, "title"))}">${esc(v.severity)}: ${esc(fl(v, "title"))}${c}</span>`; });
  (h.vuln || []).forEach(v => { b += `<span class="bdg ${SEVCLS[v.severity] || ""}" data-tip="${esc(fl(v, "evidence") || fl(v, "title"))}">${esc(v.severity)}: ${esc(fl(v, "title"))}</span>`; });
  if (h.wildcard) b += `<span class="bdg" data-tip="${esc(explainRec("wildcard"))}">${t("wild")}</span>`;
  (h.exposed_flags || []).forEach(f => { b += `<span class="bdg warn" data-tip="${esc(explainRec("exposed"))}">${esc(f)}</span>`; });
  return b;
}

const PQ_VERDICT = {hybrid: {hu: "kvantum-biztos (hibrid)", en: "quantum-safe (hybrid)"},
                    classical: {hu: "klasszikus — HNDL-kockázat", en: "classical — HNDL risk"},
                    unknown: {hu: "ismeretlen", en: "unknown"}};
function pqBlock(pq) {
  const k = pq.kex || {}, c = pq.cert || {};
  const cls = pq.verdict === "hybrid" ? "good" : pq.verdict === "classical" ? "warn" : "";
  const lang = L().startsWith("hu") ? "hu" : "en";
  const vtxt = (PQ_VERDICT[pq.verdict] || PQ_VERDICT.unknown)[lang];
  const parts = [];
  if (k.group) parts.push(`${lang === "hu" ? "kulcscsere" : "key exchange"}: ${esc(k.group)}`);
  if (k.tls) parts.push(`TLS ${esc(k.tls)}`);
  if (c.key_alg) parts.push(`cert: ${esc(c.key_alg)}${c.key_bits ? " " + c.key_bits : ""}`);
  if (c.sig_alg) parts.push(`${lang === "hu" ? "aláírás" : "signature"}: ${esc(c.sig_alg)}`);
  return `<div class="kv" data-tip="${esc(explainRec("pq"))}"><b>${t("d_pq")}:</b> `
    + `<span class="bdg ${cls}">${esc(vtxt)}</span> ${parts.map(p => `<span class="tag">${p}</span>`).join(" ")}</div>`;
}

function portChip(p) {
  const cls = !p.expected ? (p.name && /HTTP|HTTPS/i.test(p.name) ? "web" : "svc") : "exp";
  return `<span class="port ${cls}" data-tip="${esc(explainPort(p.port, p.name))}">${p.port}${p.name && p.name !== "?" ? " " + esc(p.name) : ""}</span>`;
}

function renderHostRow(h) {
  const ports = h.ports || [];
  const cls = hostClass(h);
  const liveLabel = hasTakeover(h) ? "takeover" : (cls === "exposed" ? t("exposed") : h.alive ? t("live_yes") : t("live_no"));
  const chips = ports.length ? ports.slice(0, 6).map(portChip).join("") + (ports.length > 6 ? `<span class="tag">+${ports.length - 6}</span>` : "") : "";
  const portHtml = (chips + badges(h)) || `<span class="empty" style="margin:0">—</span>`;   // portok + találat-badge-ek
  const open = ["cve", "exposed", "takeover"].includes(liveFilter) && (isExposed(h) || hasTakeover(h)) ? " open" : "";
  return `<details class="hrow ${cls}"${open}>
    <summary>
      <span class="dot"></span>
      <span class="hname"><b>${esc(h.host)}</b><small>${liveLabel}${h.cname ? " · CNAME " + esc(h.cname) : ""}${h.source_brute ? " · brute" : ""}</small></span>
      <span class="hips">${ipShort(h)}</span>
      <span class="hports">${portHtml}</span>
      <span class="hcount">${ports.length || ""}</span>
    </summary>
    ${renderDetail(h)}
  </details>`;
}

function cveBlock(h) {
  if (!(h.cve && h.cve.length)) return "";
  const grp = (m, label) => {
    const items = h.cve.filter(v => (v.method || "version") === m);
    if (!items.length) return "";
    return `<div class="kv"><b>${label}:</b> ` + items.map(v => {
      const c = v.cve && v.cve !== "—" ? " (" + esc(v.cve) + ")" : "";
      return `<span class="bdg ${SEVCLS[v.severity] || "bad"}" data-tip="${esc(fl(v, "evidence"))}">${esc(v.severity)}: ${esc(fl(v, "title"))}${c}</span>`;
    }).join(" ") + "</div>";
  };
  return grp("version", t("d_cve_ver")) + grp("fingerprint", t("d_cve_fp"));
}

function renderDetail(h) {
  const ipsTable = (h.ips_info && h.ips_info.length) ? `<div class="tablewrap"><table>
    <tr><th>IP</th><th data-tip="${esc(explainRec("ptr"))}">PTR</th><th data-tip="${esc(explainRec("asn"))}">ASN</th><th>Org</th><th>CC</th></tr>` +
    h.ips_info.map(i => `<tr><td class="m">${esc(i.ip)}</td><td class="m">${esc(i.ptr || "—")}</td>
      <td class="m">${i.asn ? "AS" + esc(i.asn) : "—"}</td><td class="m">${esc(i.org || "—")}</td><td class="m">${esc(i.cc || "—")}</td></tr>`).join("")
    + "</table></div>" : (h.ips || []).length ? `<div class="kv"><b>${t("d_ips")}:</b> ${esc(h.ips.join(", "))}</div>` : "";

  const tk = hasTakeover(h) ? `<div class="kv" data-tip="${esc(explainRec("takeover"))}"><b>${t("d_takeover")}:</b>
     ${esc(h.takeover.service)} → ${esc(h.takeover.cname)} · ${h.takeover.confirmed ? t("confirmed") : t("suspected")}</div>` : "";
  const tech = (h.tech && h.tech.length) ? `<div class="kv"><b>${t("d_tech")}:</b> ${h.tech.map(x => `<span class="tag">${esc(x)}</span>`).join(" ")}</div>` : "";
  const exp = (h.exposed_flags && h.exposed_flags.length) ? `<div class="kv" data-tip="${esc(explainRec("exposed"))}"><b>${t("d_exposed")}:</b> ${h.exposed_flags.map(x => `<span class="tag san">${esc(x)}</span>`).join(" ")}</div>` : "";
  const vuln = (h.vuln && h.vuln.length) ? `<div class="kv"><b>${t("d_vuln")}:</b> ${h.vuln.map(v => `<span class="bdg ${SEVCLS[v.severity] || ""}" data-tip="${esc(fl(v, "evidence"))}">${esc(v.severity)}: ${esc(fl(v, "title"))}</span>`).join(" ")}</div>` : "";
  const cve = cveBlock(h);
  const pq = h.pq && h.pq.kex ? pqBlock(h.pq) : "";
  const sans = (h.tls_sans && h.tls_sans.length) ? `<div class="kv"><b>${t("d_sans")}:</b> ${h.tls_sans.map(s => `<span class="tag san">${esc(s)}</span>`).join(" ")}</div>` : "";

  let portsTbl = "";
  if ((h.ports || []).length) {
    portsTbl = `<div class="tablewrap"><table>
      <tr><th>${t("t_port")}</th><th>${t("t_svc")}</th><th>${t("t_detail")}</th><th>${t("t_rtt")}</th></tr>` +
      h.ports.map(p => {
        const http = p.http || {}, tls = p.tls || {};
        let det = [];
        if (http.status) det.push(`HTTP ${http.status}`);
        if (http.server) det.push(esc(http.server));
        if (http.powered_by) det.push(esc(http.powered_by));
        if (http.title) det.push(`„${esc(http.title)}”`);
        if ((p.tech || []).length) det.push(esc(p.tech.join(", ")));
        if (tls.cn) det.push(`CN=${esc(tls.cn)}`);
        if (p.banner) det.push(esc(p.banner));
        return `<tr><td class="m" data-tip="${esc(explainPort(p.port, p.name))}">${p.port}</td><td class="m">${esc(p.name || "?")}</td>
          <td class="m">${det.join(" · ") || "—"}</td><td class="m">${p.rtt_ms != null ? p.rtt_ms + " ms" : "—"}</td></tr>`;
      }).join("") + "</table></div>";
  }
  // domain-leltár: domainenként külön teljes passzív (aldomén-enumeráció) indítható
  const full = (!h.ip_target && /\./.test(h.host) && !/^\d+\.\d+\.\d+\.\d+$/.test(h.host))
    ? `<div class="kv"><button class="btn" type="button" data-fullscan="${esc(h.host)}">${t("d_fullscan")}</button></div>` : "";
  return `<div class="detail">
    <div class="kv">${h.cname ? `<span data-tip="${esc(explainRec("cname"))}"><b>${t("d_cname")}:</b> ${esc(h.cname)}</span>` : ""}
      <span><b>${t("d_source")}:</b> ${h.source_brute ? "brute" : "passzív"}</span></div>
    ${ipsTable}${tk}${cve}${vuln}${pq}${tech}${exp}${sans}${portsTbl}${full}</div>`;
}

async function startScanFor(host) {   // egy domain teljes passzív vizsgálata a leltárból
  clearImport();
  $("#domain").value = host;
  await startScan();
}
document.addEventListener("click", ev => {
  const b = ev.target.closest && ev.target.closest("[data-fullscan]");
  if (b) { ev.preventDefault(); startScanFor(b.dataset.fullscan); }
});

// ---- előzmények ----
async function loadHistory() {
  let d;
  try { d = await (await fetch("/api/scans", {cache: "no-store"})).json(); }
  catch (e) { return; }
  const box = $("#history");
  const scans = d.scans || [];
  if (!scans.length) { box.innerHTML = `<p class="empty">${t("hist_empty")}</p>`; return; }
  box.innerHTML = scans.map(s => {
    const when = new Date(s.created * 1000).toLocaleString(L());
    const act = s.active_status && s.active_status !== "none" ? " + " + t("phase_active") + " " + t("st_" + s.active_status) : "";
    return `<a href="#${s.id}" data-id="${s.id}">
      <span><b>${esc(s.domain)}</b> <span class="hd">· ${t("st_" + s.status)}${act} · ${s.n_live}/${s.n_hosts} ${t("m_live").toLowerCase()} · ${s.n_ports} ${t("m_ports").toLowerCase()}</span></span>
      <span class="hd">${when}</span>
      <button class="btn danger" type="button" data-del="${s.id}">✕</button></a>`;
  }).join("");
  box.querySelectorAll("a[data-id]").forEach(a => a.addEventListener("click", ev => { if (ev.target.dataset.del) return; ev.preventDefault(); openScan(a.dataset.id); }));
  box.querySelectorAll("button[data-del]").forEach(b => b.addEventListener("click", async ev => {
    ev.preventDefault(); ev.stopPropagation();
    if (!confirm(t("confirm_del"))) return;
    await fetch(`/api/scan/${b.dataset.del}`, {method: "DELETE"});
    if (current === b.dataset.del) resetView();
    loadHistory();
  }));
}

async function openScan(id) {
  current = id; bruteSuggested = false;
  try { history.replaceState(null, "", `#${id}`); } catch (e) { /* no-op */ }
  $("#results").classList.remove("hide");
  startPoll();
  window.scrollTo({top: 0, behavior: "smooth"});
}

function resetView() {
  current = null; stopPoll();
  ["results", "stats", "progcard", "posture", "activecard", "cvecard"].forEach(id => $("#" + id).classList.add("hide"));
}

// ---- vezérlők ----
$("#go").addEventListener("click", startScan);
$("#domain").addEventListener("keydown", e => { if (e.key === "Enter") startScan(); });
$("#domain").addEventListener("input", () => { if (importedIps) clearImport(); });
$("#importbtn").addEventListener("click", () => $("#importfile").click());
$("#importfile").addEventListener("change", onImportFile);
$("#activego").addEventListener("click", startActive);
$("#cvego").addEventListener("click", startCve);
$("#subgo").addEventListener("click", startSubdomains);
$("#filter").addEventListener("input", renderHosts);
$("#cancel").addEventListener("click", async () => { if (current) await fetch(`/api/scan/${current}/cancel`, {method: "POST"}); });
$("#newscan").addEventListener("click", () => { resetView(); try { history.replaceState(null, "", location.pathname); } catch (e) { /* no-op */ } $("#domain").focus(); });
$$(".langs button").forEach(b => b.addEventListener("click", () => { setLang(b.dataset.lang); if (current) { renderStats(); renderPosture(scan); renderHosts(); } loadHistory(); }));
$("#theme").addEventListener("click", () => { const r = document.documentElement, n = r.dataset.theme === "light" ? "dark" : "light"; r.dataset.theme = n; try { localStorage.setItem("theme", n); } catch (e) { /* no-op */ } });

applyStatic();
(async () => { try { const v = await (await fetch("/api/version", {cache: "no-store"})).json(); $("#ver").textContent = "v" + v.version + (v.build ? " · " + v.build : ""); } catch (e) { /* no-op */ } })();
loadHistory();
const h = location.hash.replace("#", "");
if (/^[0-9a-f]{16}$/.test(h)) openScan(h);
