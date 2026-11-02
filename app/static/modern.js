"use strict";
// modern-dizajn 1.0 – a stílushoz tartozó viselkedés (keretrendszer nélkül, inline kód nélkül: CSP script-src 'self').
// 1) Mobilon a .table sorai kártyák: minden cella data-l címkét kap a fejlécből (dinamikusan betöltött táblákra is).
// 2) Felugró elemek: [data-toggle="<id>"] gomb nyitja/zárja a #<id> elemet (aria-expanded), kívülre kattintás és Escape zár.
// 3) Ikonsáv: a csoport felugró listája kattintás után bezárul, amíg az egér el nem hagyja a csoportot.
(function () {
  function labelTables(root) {
    const t0 = root.closest && root.closest("table.table");
    const tables = t0 ? [t0] : root.querySelectorAll ? root.querySelectorAll("table.table") : [];
    for (const t of tables) {
      const hs = [...t.querySelectorAll("thead th")].map((th) => th.textContent.trim());
      if (!hs.length) continue;
      for (const tr of t.querySelectorAll("tbody tr")) {
        let i = 0;
        for (const td of tr.children) { if (hs[i] && !td.hasAttribute("data-l")) td.setAttribute("data-l", hs[i]); i += td.colSpan || 1; }
      }
    }
  }
  labelTables(document);
  new MutationObserver((ms) => { for (const m of ms) for (const n of m.addedNodes) if (n.nodeType === 1) labelTables(n); })
    .observe(document.documentElement, { childList: true, subtree: true });

  const close = (btn) => { const el = document.getElementById(btn.dataset.toggle); if (el) el.hidden = true; btn.setAttribute("aria-expanded", "false"); };
  document.addEventListener("click", (e) => {
    const btn = e.target.closest("[data-toggle]");
    document.querySelectorAll('[data-toggle][aria-expanded="true"]').forEach((b) => {
      const el = document.getElementById(b.dataset.toggle);
      if (b !== btn && !(el && el.contains(e.target) && !e.target.closest("a"))) close(b);
    });
    if (btn) {
      const el = document.getElementById(btn.dataset.toggle); if (!el) return;
      el.hidden = !el.hidden; btn.setAttribute("aria-expanded", String(!el.hidden));
    }
    const link = e.target.closest(".nav a");
    if (link) { link.blur(); link.closest(".nav-group")?.classList.add("nofly"); }
  });
  document.addEventListener("keydown", (e) => {
    if (e.key !== "Escape") return;
    document.querySelectorAll('[data-toggle][aria-expanded="true"]').forEach((b) => { close(b); b.focus(); });
  });
  document.addEventListener("mouseout", (e) => {
    const g = e.target.closest && e.target.closest(".nav-group.nofly");
    if (g && !g.contains(e.relatedTarget)) g.classList.remove("nofly");
  });
  document.addEventListener("focusin", (e) => { const g = e.target.closest && e.target.closest(".nav-group.nofly"); if (g) g.classList.remove("nofly"); });
})();
