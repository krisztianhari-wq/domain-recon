// Téma a renderelés előtt (villanás nélkül). Alap: sötét; a választás csak ebben a böngészőben marad meg.
(function () {
  var t = null;
  try { t = localStorage.getItem("theme"); } catch (e) { /* privát mód */ }
  if (!t && window.matchMedia && matchMedia("(prefers-color-scheme: light)").matches) t = "light";
  document.documentElement.dataset.theme = t === "light" ? "light" : "dark";
})();
