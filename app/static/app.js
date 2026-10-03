// domain-recon – kliens: passzív + aktív fázis, posture, gazdagítás, hover-infók. Szövegek: i18n.js
"use strict";
const $ = s => document.querySelector(s);
const $$ = s => [...document.querySelectorAll(s)];
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[c]));
const L = () => t("locale");

let current = null, poll = null, hosts = [], scan = {}, liveFilter = "all";

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
  if (!domain) { $("#domain").focus(); return; }
  $("#go").disabled = true;
  try {
    const r = await fetch("/api/scan", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({domain})});
    if (!r.ok) { const e = await r.json().catch(() => ({})); alert(e.detail || t("err_start")); $("#go").disabled = false; return; }
    const s = await r.json();
    current = s.id;
    try { history.replaceState(null, "", `#${s.id}`); } catch (e) { /* no-op */ }
    $("#results").classList.remove("hide");
    $("#progcard").classList.remove("hide");
    startPoll();
  } catch (e) { alert(t("err_start")); $("#go").disabled = false; }
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

function startPoll() { stopPoll(); tick(); poll = setInterval(tick, 1500); }
function stopPoll() { if (poll) { clearInterval(poll); poll = null; } }

async function tick() {
  if (!current) return;
  let s;
  try { s = await (await fetch(`/api/scan/${current}`, {cache: "no-store"})).json(); }
  catch (e) { return; }
  scan = s; hosts = s.hosts || [];
  renderProgress(s); renderActive(s); renderStats(); renderPosture(s); renderHosts();
  $("#md").href = `/api/export/${current}.md`;
  $("#xlsx").href = `/api/export/${current}.xlsx`;
  $("#csv").href = `/api/export/${current}.csv`;
  $("#json").href = `/api/export/${current}.json`;
  $("#graphlink").href = `/graph#${current}`;
  const passiveDone = ["done", "error", "canceled"].includes(s.status);
  const activeIdle = !["queued", "running"].includes(s.active_status);
  if (passiveDone && activeIdle) { stopPoll(); $("#go").disabled = false; $("#activego").disabled = false; loadHistory(); }
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
function isExposed(h) { return !!((h.exposed_flags && h.exposed_flags.length) || (h.vuln && h.vuln.length)); }
function hasTakeover(h) { return h.takeover && h.takeover.service; }

function renderStats() {
  const live = hosts.filter(h => h.alive).length;
  const tk = hosts.filter(hasTakeover).length;
  const openPorts = hosts.reduce((a, h) => a + (h.ports || []).length, 0);
  const exposed = hosts.filter(isExposed).length;
  $("#stats").classList.remove("hide");
  $("#stats").innerHTML = `
    <div class="stat accent"><b>${t("m_hosts")}</b><span>${hosts.length}</span></div>
    <div class="stat good"><b>${t("m_live")}</b><span>${live}</span></div>
    <div class="stat ${tk ? "bad" : ""}" data-tip="${esc(explainRec("takeover"))}"><b>${t("m_takeover")}</b><span>${tk}</span></div>
    <div class="stat ${exposed ? "warn" : ""}"><b>${t("m_exposed")}</b><span>${exposed}</span></div>
    <div class="stat"><b>${t("m_ports")}</b><span>${openPorts}</span></div>`;
}

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
  (h.vuln || []).forEach(v => { b += `<span class="bdg ${SEVCLS[v.severity] || ""}" data-tip="${esc(v.evidence || v.title)}">${esc(v.severity)}: ${esc(v.title)}</span>`; });
  if (h.wildcard) b += `<span class="bdg" data-tip="${esc(explainRec("wildcard"))}">${t("wild")}</span>`;
  (h.exposed_flags || []).forEach(f => { b += `<span class="bdg warn" data-tip="${esc(explainRec("exposed"))}">${esc(f)}</span>`; });
  return b;
}

function portChip(p) {
  const cls = !p.expected ? (p.name && /HTTP|HTTPS/i.test(p.name) ? "web" : "svc") : "exp";
  return `<span class="port ${cls}" data-tip="${esc(explainPort(p.port, p.name))}">${p.port}${p.name && p.name !== "?" ? " " + esc(p.name) : ""}</span>`;
}

function renderHostRow(h) {
  const ports = h.ports || [];
  const cls = hostClass(h);
  const liveLabel = hasTakeover(h) ? "takeover" : (cls === "exposed" ? t("exposed") : h.alive ? t("live_yes") : t("live_no"));
  const portHtml = ports.length ? ports.slice(0, 6).map(portChip).join("") + (ports.length > 6 ? `<span class="tag">+${ports.length - 6}</span>` : "")
    : (badges(h) || `<span class="empty" style="margin:0">—</span>`);
  return `<details class="hrow ${cls}">
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
  const vuln = (h.vuln && h.vuln.length) ? `<div class="kv"><b>${t("d_vuln")}:</b> ${h.vuln.map(v => `<span class="bdg ${SEVCLS[v.severity] || ""}" data-tip="${esc(v.evidence || "")}">${esc(v.severity)}: ${esc(v.title)}</span>`).join(" ")}</div>` : "";
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
  return `<div class="detail">
    <div class="kv">${h.cname ? `<span data-tip="${esc(explainRec("cname"))}"><b>${t("d_cname")}:</b> ${esc(h.cname)}</span>` : ""}
      <span><b>${t("d_source")}:</b> ${h.source_brute ? "brute" : "passzív"}</span></div>
    ${ipsTable}${tk}${vuln}${tech}${exp}${sans}${portsTbl}</div>`;
}

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
  current = id;
  try { history.replaceState(null, "", `#${id}`); } catch (e) { /* no-op */ }
  $("#results").classList.remove("hide");
  startPoll();
  window.scrollTo({top: 0, behavior: "smooth"});
}

function resetView() {
  current = null; stopPoll();
  ["results", "stats", "progcard", "posture", "activecard"].forEach(id => $("#" + id).classList.add("hide"));
}

// ---- vezérlők ----
$("#go").addEventListener("click", startScan);
$("#domain").addEventListener("keydown", e => { if (e.key === "Enter") startScan(); });
$("#activego").addEventListener("click", startActive);
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
