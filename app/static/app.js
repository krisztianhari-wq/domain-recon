// domain-recon – kliens: vizsgálat indítása, folyamat-lekérdezés, eredménylista. Szövegek: i18n.js
"use strict";
const $ = s => document.querySelector(s);
const $$ = s => [...document.querySelectorAll(s)];
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[c]));
const L = () => t("locale");

let current = null;       // aktuális scan id
let poll = null;          // poll timer
let hosts = [];           // utolsó host-lista
let liveFilter = "all";

// --- opció-szegmensek ---
function segValue(id) { const b = $(`#${id} button.on`); return b ? b.dataset.v : null; }
$$("#ports button, #intensity button, #livefilter button").forEach(b => {
  b.addEventListener("click", () => {
    b.parentElement.querySelectorAll("button").forEach(x => x.classList.remove("on"));
    b.classList.add("on");
    if (b.parentElement.id === "ports") $("#customwrap").classList.toggle("hide", b.dataset.v !== "custom");
    if (b.parentElement.id === "livefilter") { liveFilter = b.dataset.v; renderHosts(); }
  });
});

// --- indítás ---
async function startScan() {
  const domain = $("#domain").value.trim();
  if (!domain) { $("#domain").focus(); return; }
  const body = {
    domain,
    ports: segValue("ports"),
    custom_ports: $("#customports").value.trim(),
    intensity: segValue("intensity"),
    ct: $("#ct").checked,
    wordlist: $("#wordlist").checked,
    scan_ports: $("#scanports").checked,
    allow_private: $("#allowprivate").checked,
  };
  $("#go").disabled = true;
  try {
    const r = await fetch("/api/scan", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body)});
    if (!r.ok) { const e = await r.json().catch(() => ({})); alert(e.detail || t("err_start")); $("#go").disabled = false; return; }
    const s = await r.json();
    current = s.id;
    try { history.replaceState(null, "", `#${s.id}`); } catch (e) { /* no-op */ }
    $("#results").classList.remove("hide");
    $("#progcard").classList.remove("hide");
    startPoll();
  } catch (e) {
    alert(t("err_start")); $("#go").disabled = false;
  }
}

function startPoll() {
  stopPoll();
  tick();
  poll = setInterval(tick, 1500);
}
function stopPoll() { if (poll) { clearInterval(poll); poll = null; } }

async function tick() {
  if (!current) return;
  let s;
  try { s = await (await fetch(`/api/scan/${current}`, {cache: "no-store"})).json(); }
  catch (e) { return; }
  renderProgress(s);
  const note = $("#scannote");
  note.textContent = s.note || "";
  note.classList.toggle("hide", !s.note);
  hosts = s.hosts || [];
  renderStats(s);
  renderHosts();
  $("#csv").href = `/api/export/${current}.csv`;
  $("#json").href = `/api/export/${current}.json`;
  if (["done", "error", "canceled"].includes(s.status)) {
    stopPoll();
    $("#go").disabled = false;
    loadHistory();
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
  else {
    const pct = s.total ? Math.round(s.done / s.total * 100) : (s.status === "done" ? 100 : 0);
    fill.style.width = pct + "%";
    $("#progtxt").textContent = `${s.done || 0} / ${s.total || 0}`;
  }
  const op = s.opts || {};
  $("#scanmeta").textContent = `${esc(s.domain || "")} · ${op.profile || op.ports || ""} · ${t("i_" + (op.intensity || "polite"))}`;
  $("#cancel").classList.toggle("hide", !running);
  if (s.status === "error" && s.error) $("#scanmeta").textContent = s.error;
}

function isExposed(h) { return (h.ports || []).some(p => !p.expected); }

function renderStats(s) {
  const live = hosts.filter(h => h.alive).length;
  const exposed = hosts.filter(isExposed).length;
  const openPorts = hosts.reduce((a, h) => a + (h.ports || []).length, 0);
  $("#stats").classList.remove("hide");
  $("#stats").innerHTML = `
    <div class="stat accent"><b>${t("m_hosts")}</b><span>${hosts.length}</span></div>
    <div class="stat good"><b>${t("m_live")}</b><span>${live}</span></div>
    <div class="stat ${exposed ? "warn" : ""}"><b>${t("m_exposed")}</b><span>${exposed}</span></div>
    <div class="stat"><b>${t("m_ports")}</b><span>${openPorts}</span></div>`;
}

function portChip(p) {
  const cls = !p.expected ? (p.name && /HTTP|HTTPS/i.test(p.name) ? "web" : "svc") : "exp";
  return `<span class="port ${cls}" title="${esc(p.name || "")}">${p.port}${p.name && p.name !== "?" ? " " + esc(p.name) : ""}</span>`;
}

function hostClass(h) {
  if (!h.alive) return "dead";
  if (isExposed(h)) return "exposed";
  return "live";
}

function matchFilter(h, q) {
  if (!q) return true;
  const hay = [h.host, (h.ips || []).join(" "), h.cname || "",
               (h.ports || []).map(p => p.port + " " + (p.name || "")).join(" ")].join(" ").toLowerCase();
  return hay.includes(q);
}

function renderHosts() {
  const q = ($("#filter").value || "").trim().toLowerCase();
  let list = hosts.filter(h => matchFilter(h, q));
  if (liveFilter === "live") list = list.filter(h => h.alive);
  else if (liveFilter === "dead") list = list.filter(h => !h.alive);
  else if (liveFilter === "exposed") list = list.filter(isExposed);
  // rendezés: kitett → élő → nem élő, azon belül név
  const rank = h => (isExposed(h) ? 0 : h.alive ? 1 : 2);
  list.sort((a, b) => rank(a) - rank(b) || a.host.localeCompare(b.host));
  const box = $("#hostlist");
  if (!list.length) { box.innerHTML = `<p class="empty" style="padding:14px">${hosts.length ? t("none") : t("no_hosts")}</p>`; return; }
  box.innerHTML = list.map(renderHostRow).join("");
}

function renderHostRow(h) {
  const ips = (h.ips || []);
  const ports = h.ports || [];
  const cls = hostClass(h);
  const liveLabel = cls === "exposed" ? t("exposed") : h.alive ? t("live_yes") : t("live_no");
  const portHtml = ports.length ? ports.slice(0, 6).map(portChip).join("") + (ports.length > 6 ? `<span class="tag">+${ports.length - 6}</span>` : "")
    : `<span class="empty" style="margin:0">—</span>`;
  const detail = renderDetail(h);
  return `<details class="hrow ${cls}">
    <summary>
      <span class="dot"></span>
      <span class="hname"><b>${esc(h.host)}</b><small>${liveLabel}${h.cname ? " · CNAME " + esc(h.cname) : ""}</small></span>
      <span class="hips" title="${esc(ips.join(", "))}">${esc(ips.slice(0, 2).join(", ")) || "—"}${ips.length > 2 ? " +" + (ips.length - 2) : ""}</span>
      <span class="hports">${portHtml}</span>
      <span class="hcount">${ports.length || ""}</span>
    </summary>
    ${detail}
  </details>`;
}

function renderDetail(h) {
  const ips = (h.ips || []);
  const ports = h.ports || [];
  let rows = "";
  if (ports.length) {
    rows = `<div class="tablewrap"><table>
      <tr><th>${t("t_port")}</th><th>${t("t_svc")}</th><th>${t("t_detail")}</th><th>${t("t_rtt")}</th></tr>` +
      ports.map(p => {
        const http = p.http || {}, tls = p.tls || {};
        let det = [];
        if (http.status) det.push(`HTTP ${http.status}`);
        if (http.server) det.push(esc(http.server));
        if (http.title) det.push(`„${esc(http.title)}”`);
        if (tls.cn) det.push(`CN=${esc(tls.cn)}`);
        if (p.banner) det.push(esc(p.banner));
        return `<tr><td class="m">${p.port}</td><td class="m">${esc(p.name || "?")}</td>
          <td class="m">${det.join(" · ") || "—"}</td><td class="m">${p.rtt_ms != null ? p.rtt_ms + " ms" : "—"}</td></tr>`;
      }).join("") + "</table></div>";
  }
  const sans = h.tls_sans && h.tls_sans.length
    ? `<div class="kv"><b>${t("d_sans")}:</b> ${h.tls_sans.map(s => `<span class="tag san">${esc(s)}</span>`).join(" ")}</div>` : "";
  return `<div class="detail">
    <div class="kv">
      <span><b>${t("d_ips")}:</b> ${esc(ips.join(", ")) || "—"}</span>
      ${h.cname ? `<span><b>${t("d_cname")}:</b> ${esc(h.cname)}</span>` : ""}
      <span><b>${t("d_source")}:</b> ${esc(h.source || "ct/seed")}</span>
    </div>
    ${sans}
    ${rows || `<p class="empty" style="margin:0">${t("d_ports")}: —</p>`}
  </div>`;
}

// --- előzmények ---
async function loadHistory() {
  let d;
  try { d = await (await fetch("/api/scans", {cache: "no-store"})).json(); }
  catch (e) { return; }
  const box = $("#history");
  const scans = d.scans || [];
  if (!scans.length) { box.innerHTML = `<p class="empty">${t("hist_empty")}</p>`; return; }
  box.innerHTML = scans.map(s => {
    const when = new Date(s.created * 1000).toLocaleString(L());
    const st = t("st_" + s.status);
    return `<a href="#${s.id}" data-id="${s.id}">
      <span><b>${esc(s.domain)}</b> <span class="hd">· ${st} · ${s.n_live}/${s.n_hosts} ${t("m_live").toLowerCase()} · ${s.n_ports} ${t("m_ports").toLowerCase()}</span></span>
      <span class="hd">${when}</span>
      <button class="btn danger" type="button" data-del="${s.id}">✕</button>
    </a>`;
  }).join("");
  box.querySelectorAll("a[data-id]").forEach(a => a.addEventListener("click", ev => {
    if (ev.target.dataset.del) return;
    ev.preventDefault(); openScan(a.dataset.id);
  }));
  box.querySelectorAll("button[data-del]").forEach(b => b.addEventListener("click", async ev => {
    ev.preventDefault(); ev.stopPropagation();
    if (!confirm(t("confirm_del"))) return;
    await fetch(`/api/scan/${b.dataset.del}`, {method: "DELETE"});
    if (current === b.dataset.del) { current = null; stopPoll(); $("#results").classList.add("hide"); $("#stats").classList.add("hide"); $("#progcard").classList.add("hide"); }
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

// --- vezérlők ---
$("#go").addEventListener("click", startScan);
$("#domain").addEventListener("keydown", e => { if (e.key === "Enter") startScan(); });
$("#filter").addEventListener("input", renderHosts);
$("#cancel").addEventListener("click", async () => { if (current) await fetch(`/api/scan/${current}/cancel`, {method: "POST"}); });
$("#newscan").addEventListener("click", () => {
  current = null; stopPoll();
  $("#results").classList.add("hide"); $("#stats").classList.add("hide"); $("#progcard").classList.add("hide");
  try { history.replaceState(null, "", location.pathname); } catch (e) { /* no-op */ }
  $("#domain").focus();
});
$$(".langs button").forEach(b => b.addEventListener("click", () => { setLang(b.dataset.lang); renderStats({}); renderHosts(); loadHistory(); }));
$("#theme").addEventListener("click", () => {
  const root = document.documentElement, next = root.dataset.theme === "light" ? "dark" : "light";
  root.dataset.theme = next;
  try { localStorage.setItem("theme", next); } catch (e) { /* no-op */ }
});

applyStatic();
loadHistory();
// mély link: #<scanid>
const h = location.hash.replace("#", "");
if (/^[0-9a-f]{16}$/.test(h)) openScan(h);
