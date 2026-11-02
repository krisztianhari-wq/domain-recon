// Téma a renderelés előtt (villanás nélkül). Alap: világos (modern-dizajn); a választás csak ebben a böngészőben marad meg.
(function () {
  var t = null;
  try { t = localStorage.getItem("theme"); } catch (e) { /* privát mód */ }
  if (!t && window.matchMedia && matchMedia("(prefers-color-scheme: dark)").matches) t = "dark";
  document.documentElement.dataset.theme = t === "dark" ? "dark" : "light";
})();
