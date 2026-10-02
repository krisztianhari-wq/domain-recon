// domain-recon – kapcsolati gráf. Vanilla JS + inline SVG, külső könyvtár nélkül.
// Elrendezés: koncentrikus körök. Középen a domain, 1. gyűrű az élő hostok,
// 2. gyűrű az egyedi IP-k, 3. gyűrű az egyedi ASN-ek. Az éleket a csomópontok
// között húzzuk (domain→host, host→ip, ip→asn), az IP/ASN csomópontokat dedupláljuk.
"use strict";

(function () {
  const SVGNS = "http://www.w3.org/2000/svg";
  const VB = 1400;                 // belső koordinátarendszer (négyzet)
  const CX = VB / 2, CY = VB / 2;
  const R1 = 240, R2 = 440, R3 = 620;   // host / ip / asn gyűrűk sugara
  const HOST_CAP = 120;            // ennyi hostot rajzolunk legfeljebb

  const $ = (s) => document.querySelector(s);
  const svg = $("#graph");
  const tip = $("#tip");

  // --- apró, kétnyelvű felületi szövegek (i18n.js t()-jét nem erőltetjük rá) ---
  const L = {
    hu: {
      eyebrow: "Támadási felület · kapcsolati gráf",
      h1: "Kapcsolati gráf",
      sub: "Domain → hostok → IP-címek → ASN / szervezet. Húzással mozgatható, görgővel nagyítható.",
      back: "← Vissza", meta: (d, h, i, a) => `${d} · ${h} host · ${i} IP · ${a} ASN`,
      trunc: (n) => `(csak az első ${n} host látszik)`,
      noid: "Nincs megadva vizsgálat-azonosító.",
      fail: "A vizsgálat nem tölthető be.",
      empty: "Ehhez a vizsgálathoz nincs megjeleníthető host.",
      tolist: "Vissza a listához",
      host: "host", ip: "IP-cím", asn: "ASN / szervezet", takeover: "lehetséges takeover",
      ptr: "PTR", cc: "ország", ips: "IP-k", of: "ehhez",
    },
    en: {
      eyebrow: "Attack surface · relationship graph",
      h1: "Relationship graph",
      sub: "Domain → hosts → IP addresses → ASN / organisation. Drag to pan, scroll to zoom.",
      back: "← Back", meta: (d, h, i, a) => `${d} · ${h} hosts · ${i} IPs · ${a} ASN`,
      trunc: (n) => `(showing first ${n} hosts only)`,
      noid: "No scan id provided.",
      fail: "Could not load the scan.",
      empty: "No hosts to display for this scan.",
      tolist: "Back to the list",
      host: "host", ip: "IP address", asn: "ASN / organisation", takeover: "possible takeover",
      ptr: "PTR", cc: "country", ips: "IPs", of: "for",
    },
  };
  let lang = (typeof LANG !== "undefined" && L[LANG]) ? LANG : "hu";
  const tr = () => L[lang] || L.hu;

  // --- vizsgálat-azonosító: előbb #hash, aztán ?id= ---
  function getId() {
    const h = (location.hash || "").replace(/^#/, "").trim();
    if (/^[0-9a-f]{16}$/i.test(h)) return h.toLowerCase();
    const q = new URLSearchParams(location.search).get("id");
    if (q && /^[0-9a-f]{16}$/i.test(q)) return q.toLowerCase();
    return (h || q || "").trim() || null;   // engedékeny: a szerver amúgy is validál
  }

  function el(tag, attrs) {
    const e = document.createElementNS(SVGNS, tag);
    if (attrs) for (const k in attrs) e.setAttribute(k, attrs[k]);
    return e;
  }

  function showMessage(txt) {
    while (svg.firstChild) svg.removeChild(svg.firstChild);
    const fo = el("foreignObject", { x: 0, y: 0, width: VB, height: VB });
    const div = document.createElement("div");
    div.className = "gmsg";
    div.setAttribute("xmlns", "http://www.w3.org/1999/xhtml");
    const id = getId();
    const href = id ? "/#" + encodeURIComponent(id) : "/";
    div.appendChild(document.createTextNode(txt + " "));
    const a = document.createElement("a");
    a.href = "/";
    a.textContent = tr().tolist;
    div.appendChild(a);
    fo.appendChild(div);
    svg.appendChild(fo);
  }

  // --- tooltip ---
  function tipShow(html, x, y) {
    tip.innerHTML = html;                 // csak saját, megbízható (escape-elt) szöveg
    tip.classList.add("on");
    moveTip(x, y);
  }
  function moveTip(x, y) {
    const pad = 14;
    let left = x + pad, top = y + pad;
    const w = tip.offsetWidth, h = tip.offsetHeight;
    if (left + w > window.innerWidth - 8) left = x - w - pad;
    if (top + h > window.innerHeight - 8) top = y - h - pad;
    tip.style.left = Math.max(8, left) + "px";
    tip.style.top = Math.max(8, top) + "px";
  }
  function tipHide() { tip.classList.remove("on"); }

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"]/g, (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  }

  // --- adat → gráf ---
  function build(scan) {
    const T = tr();
    const domain = scan.domain || "domain";
    const allHosts = Array.isArray(scan.hosts) ? scan.hosts : [];
    let hosts = allHosts.filter((h) => h && h.alive && h.ips && h.ips.length);
    // ha nincs „élő” host, essünk vissza bármely hostra, aminek van IP-je
    if (!hosts.length) hosts = allHosts.filter((h) => h && h.ips && h.ips.length);
    const truncated = hosts.length > HOST_CAP;
    if (truncated) hosts = hosts.slice(0, HOST_CAP);

    if (!hosts.length) { showMessage(T.empty); return { ok: false }; }

    // egyedi IP- és ASN-csomópontok
    const ipMap = new Map();   // ip -> {ip, ptr, cc, asnKey}
    const asnMap = new Map();  // asnKey -> {key, asn, org, cc, label}
    const edgesHI = [];        // host→ip
    const edgesIA = [];        // ip→asn

    hosts.forEach((h, hi) => {
      const info = {};
      (h.ips_info || []).forEach((r) => { if (r && r.ip) info[r.ip] = r; });
      (h.ips || []).forEach((ip) => {
        if (!ipMap.has(ip)) {
          const r = info[ip] || {};
          let asnKey = null;
          if (r.asn) {
            asnKey = "AS" + r.asn;
            if (!asnMap.has(asnKey)) {
              const org = r.org || "";
              asnMap.set(asnKey, { key: asnKey, asn: r.asn, org: org, cc: r.cc || "",
                label: ("AS" + r.asn + (org ? " " + org : "")).slice(0, 42) });
            }
          }
          ipMap.set(ip, { ip: ip, ptr: r.ptr || "", cc: r.cc || "", asnKey: asnKey });
        }
        edgesHI.push([hi, ip]);
        const node = ipMap.get(ip);
        if (node.asnKey) edgesIA.push([ip, node.asnKey]);
      });
    });

    // --- szögek: a kapcsolódó elemeket nagyjából egy irányba rendezzük (kevesebb metszés) ---
    const hostAngle = new Map();
    const n = hosts.length;
    hosts.forEach((h, i) => hostAngle.set(i, (i / n) * Math.PI * 2 - Math.PI / 2));

    // IP szöge = a hozzá kapcsolódó hostok átlagszöge
    const ipHostAngles = new Map();
    edgesHI.forEach(([hi, ip]) => {
      if (!ipHostAngles.has(ip)) ipHostAngles.set(ip, []);
      ipHostAngles.get(ip).push(hostAngle.get(hi));
    });
    const ips = Array.from(ipMap.keys());
    const ipMean = (ip) => meanAngle(ipHostAngles.get(ip) || [0]);
    ips.sort((a, b) => ipMean(a) - ipMean(b));
    const ipAngle = new Map();
    const ni = ips.length;
    ips.forEach((ip, i) => ipAngle.set(ip, (i / ni) * Math.PI * 2 - Math.PI / 2));

    // ASN szöge = a hozzá kapcsolódó IP-k átlagszöge
    const asnIpAngles = new Map();
    ipMap.forEach((node, ip) => {
      if (node.asnKey) {
        if (!asnIpAngles.has(node.asnKey)) asnIpAngles.set(node.asnKey, []);
        asnIpAngles.get(node.asnKey).push(ipAngle.get(ip));
      }
    });
    const asns = Array.from(asnMap.keys());
    asns.sort((a, b) => meanAngle(asnIpAngles.get(a) || [0]) - meanAngle(asnIpAngles.get(b) || [0]));
    const asnAngle = new Map();
    const na = asns.length;
    asns.forEach((k, i) => asnAngle.set(k, (i / Math.max(na, 1)) * Math.PI * 2 - Math.PI / 2));

    // --- koordináták ---
    const pos = new Map();                       // id -> {x,y}
    pos.set("__domain__", { x: CX, y: CY });
    hosts.forEach((h, i) => pos.set("h" + i, polar(hostAngle.get(i), R1)));
    ips.forEach((ip) => pos.set("ip:" + ip, polar(ipAngle.get(ip), R2)));
    asns.forEach((k) => pos.set("as:" + k, polar(asnAngle.get(k), R3)));

    // --- rajzolás: élek alul, csomópontok felül ---
    while (svg.firstChild) svg.removeChild(svg.firstChild);
    const gEdges = el("g", { class: "edges" });
    const gNodes = el("g", { class: "nodes" });
    svg.appendChild(gEdges);
    svg.appendChild(gNodes);

    const edgeIndex = { host: new Map(), ip: new Map() };  // kiemeléshez

    // domain→host + host→ip
    hosts.forEach((h, i) => {
      const p = pos.get("h" + i);
      const line = el("line", { class: "edge e-host", x1: CX, y1: CY, x2: p.x, y2: p.y });
      gEdges.appendChild(line);
      edgeIndex.host.set("h" + i, [line]);
    });
    edgesHI.forEach(([hi, ip]) => {
      const a = pos.get("h" + hi), b = pos.get("ip:" + ip);
      if (!a || !b) return;
      const line = el("line", { class: "edge e-ip", x1: a.x, y1: a.y, x2: b.x, y2: b.y });
      gEdges.appendChild(line);
      push(edgeIndex.host, "h" + hi, line);
      push(edgeIndex.ip, "ip:" + ip, line);
    });
    edgesIA.forEach(([ip, asnKey]) => {
      const a = pos.get("ip:" + ip), b = pos.get("as:" + asnKey);
      if (!a || !b) return;
      const line = el("line", { class: "edge e-asn", x1: a.x, y1: a.y, x2: b.x, y2: b.y });
      gEdges.appendChild(line);
      push(edgeIndex.ip, "ip:" + ip, line);
    });

    // ASN csomópontok (állandó felirattal)
    asns.forEach((k) => {
      const a = asnMap.get(k), p = pos.get("as:" + k);
      const g = node("asn", p, 10, a.label + (a.cc ? " · " + a.cc : ""),
        `<b>${esc(a.label)}</b>${a.cc ? `<small>${T.cc}: ${esc(a.cc)}</small>` : ""}`);
      const txt = el("text", { class: "lbl-asn", x: p.x + 13, y: p.y + 4 });
      txt.textContent = a.label;
      g.appendChild(txt);
      gNodes.appendChild(g);
    });

    // IP csomópontok
    ips.forEach((ip) => {
      const node0 = ipMap.get(ip), p = pos.get("ip:" + ip);
      const sub = [node0.ptr ? `${T.ptr}: ${node0.ptr}` : "", node0.asnKey || ""].filter(Boolean).join(" · ");
      const g = node("ip", p, 6, ip, `<b>${esc(ip)}</b>${sub ? `<small>${esc(sub)}</small>` : ""}`);
      g.addEventListener("mouseenter", () => hl(edgeIndex.ip.get("ip:" + ip)));
      g.addEventListener("mouseleave", () => unhl());
      gNodes.appendChild(g);
    });

    // host csomópontok (kattintható → vissza a listához)
    hosts.forEach((h, i) => {
      const p = pos.get("h" + i);
      const take = h.takeover && h.takeover.service;
      const sub = [h.cname ? "CNAME: " + h.cname : "",
        take ? T.takeover + ": " + h.takeover.service : "",
        (h.ips || []).length + " " + T.ips].filter(Boolean).join(" · ");
      const g = node("host" + (take ? " takeover" : ""), p, take ? 11 : 9, h.host,
        `<b>${esc(h.host)}</b>${sub ? `<small>${esc(sub)}</small>` : ""}`);
      g.addEventListener("mouseenter", () => hl(edgeIndex.host.get("h" + i)));
      g.addEventListener("mouseleave", () => unhl());
      g.addEventListener("click", () => {
        try { location.href = "/#" + encodeURIComponent(scan.id || getId() || ""); }
        catch (e) { location.href = "/"; }
      });
      gNodes.appendChild(g);
    });

    // domain középen (állandó felirat)
    const dp = pos.get("__domain__");
    const gd = node("domain", dp, 26, domain, `<b>${esc(domain)}</b>`);
    const dt = el("text", { class: "lbl-domain", x: dp.x, y: dp.y + 46, "text-anchor": "middle" });
    dt.textContent = domain;
    gd.appendChild(dt);
    gNodes.appendChild(gd);

    return { ok: true, domain, hosts: hosts.length, ips: ni, asns: na, truncated };
  }

  // egy csomópont-csoport: kör + <title> + hover-tooltip
  function node(cls, p, r, titleText, tipHtml) {
    const g = el("g", { class: "node " + cls });
    const c = el("circle", { cx: p.x, cy: p.y, r: r });
    g.appendChild(c);
    const title = el("title");
    title.textContent = titleText;
    g.appendChild(title);
    g.addEventListener("mouseenter", (ev) => { g.classList.add("hot"); tipShow(tipHtml, ev.clientX, ev.clientY); });
    g.addEventListener("mousemove", (ev) => moveTip(ev.clientX, ev.clientY));
    g.addEventListener("mouseleave", () => { g.classList.remove("hot"); tipHide(); });
    return g;
  }

  function hl(lines) { if (lines) lines.forEach((l) => l.classList.add("hot")); }
  function unhl() { svg.querySelectorAll(".edge.hot").forEach((l) => l.classList.remove("hot")); }
  function push(map, key, v) { if (!map.has(key)) map.set(key, []); map.get(key).push(v); }
  function polar(ang, r) { return { x: CX + Math.cos(ang) * r, y: CY + Math.sin(ang) * r }; }
  function meanAngle(arr) {
    let sx = 0, sy = 0;
    arr.forEach((a) => { sx += Math.cos(a); sy += Math.sin(a); });
    return Math.atan2(sy, sx);
  }

  // --- pan + zoom (viewBox transzformáció) ---
  const view = { x: 0, y: 0, w: VB, h: VB };
  function applyView() { svg.setAttribute("viewBox", `${view.x} ${view.y} ${view.w} ${view.h}`); }
  function fit() { view.x = 0; view.y = 0; view.w = VB; view.h = VB; applyView(); }

  function clientToSvg(cx, cy) {
    const r = svg.getBoundingClientRect();
    const sx = view.w / r.width, sy = view.h / r.height;
    return { x: view.x + (cx - r.left) * sx, y: view.y + (cy - r.top) * sy };
  }
  function zoomAt(cx, cy, factor) {
    const before = clientToSvg(cx, cy);
    const nw = Math.min(VB * 3, Math.max(VB * 0.25, view.w * factor));
    const nh = nw;
    view.w = nw; view.h = nh;
    const after = clientToSvg(cx, cy);
    view.x += before.x - after.x;
    view.y += before.y - after.y;
    applyView();
  }
  function wirePanZoom() {
    svg.addEventListener("wheel", (ev) => {
      ev.preventDefault();
      zoomAt(ev.clientX, ev.clientY, ev.deltaY > 0 ? 1.12 : 1 / 1.12);
    }, { passive: false });

    let dragging = false, lastSvg = null;
    svg.addEventListener("pointerdown", (ev) => {
      if (ev.target.closest(".node")) return;     // csomóponton ne panoljunk
      dragging = true; lastSvg = clientToSvg(ev.clientX, ev.clientY);
      svg.classList.add("panning");
      try { svg.setPointerCapture(ev.pointerId); } catch (e) { /* no-op */ }
    });
    svg.addEventListener("pointermove", (ev) => {
      if (!dragging) return;
      const now = clientToSvg(ev.clientX, ev.clientY);
      view.x += lastSvg.x - now.x; view.y += lastSvg.y - now.y;
      applyView();
      lastSvg = clientToSvg(ev.clientX, ev.clientY);
    });
    const end = (ev) => {
      dragging = false; svg.classList.remove("panning");
      try { if (ev) svg.releasePointerCapture(ev.pointerId); } catch (e) { /* no-op */ }
    };
    svg.addEventListener("pointerup", end);
    svg.addEventListener("pointercancel", end);
  }

  // --- statikus szövegek + vezérlők ---
  function applyLang() {
    const T = tr();
    document.documentElement.lang = lang;
    $("#eyebrow").textContent = T.eyebrow;
    $("#h1").textContent = T.h1;
    $("#sub").textContent = T.sub;
    $("#back").textContent = T.back;
    document.querySelectorAll(".langs button").forEach((b) =>
      b.setAttribute("aria-pressed", String(b.dataset.lang === lang)));
  }

  function wireChrome(summary) {
    // téma-kapcsoló (app.js mintájára)
    const tbtn = $("#theme");
    if (tbtn) tbtn.addEventListener("click", () => {
      const r = document.documentElement, nx = r.dataset.theme === "light" ? "dark" : "light";
      r.dataset.theme = nx;
      try { localStorage.setItem("theme", nx); } catch (e) { /* privát mód */ }
    });
    // „Vissza” az adott vizsgálathoz
    const id = getId();
    const back = $("#back");
    if (back) back.setAttribute("href", id ? "/#" + encodeURIComponent(id) : "/");
    // nyelvváltó
    document.querySelectorAll(".langs button").forEach((b) => {
      b.addEventListener("click", () => {
        lang = b.dataset.lang === "en" ? "en" : "hu";
        try { if (typeof setLang === "function") setLang(lang); } catch (e) { /* no-op */ }
        applyLang();
        if (summary && summary.ok) setMeta(summary);
      });
    });
    // zoom gombok
    $("#zin").addEventListener("click", () => zoomAt(window.innerWidth / 2, window.innerHeight / 2, 1 / 1.25));
    $("#zout").addEventListener("click", () => zoomAt(window.innerWidth / 2, window.innerHeight / 2, 1.25));
    $("#zfit").addEventListener("click", fit);
  }

  function setMeta(s) {
    const T = tr();
    let m = T.meta(s.domain, s.hosts, s.ips, s.asns);
    if (s.truncated) m += " " + T.trunc(HOST_CAP);
    $("#meta").textContent = m;
  }

  // --- indítás ---
  async function main() {
    applyLang();
    wirePanZoom();
    applyView();
    const id = getId();
    if (!id) { wireChrome(null); showMessage(tr().noid); return; }
    try {
      const res = await fetch("/api/scan/" + encodeURIComponent(id), { headers: { Accept: "application/json" } });
      if (!res.ok) throw new Error("http " + res.status);
      const scan = await res.json();
      if (!scan.id) scan.id = id;
      const summary = build(scan);
      wireChrome(summary);
      if (summary && summary.ok) setMeta(summary);
    } catch (e) {
      wireChrome(null);
      showMessage(tr().fail);
    }
  }

  try { main(); }
  catch (e) {
    try { showMessage(tr().fail); } catch (e2) { /* no-op */ }
  }
})();
