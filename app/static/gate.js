// Közös cég-belépő: a kódot elküldi a /api/access-nek, siker esetén süti + újratöltés.
// A munkaterület-linket (?w=…) itt is megőrizzük, hogy belépés után a helyes workspace-be érjen.
(function () {
  "use strict";
  var form = document.getElementById("gateform");
  var inp = document.getElementById("secret");
  var btn = document.getElementById("gatebtn");
  var err = document.getElementById("gateerr");

  // ?w=… már a belépő előtt kerüljön a sütibe/localStorage-be, hogy reload után is meglegyen
  try {
    var w = new URLSearchParams(location.search).get("w");
    if (w && /^[A-Za-z0-9._-]{1,64}$/.test(w)) {
      localStorage.setItem("recon_ws", w);
      document.cookie = "recon_ws=" + w + "; path=/; max-age=7776000; samesite=lax";
    }
  } catch (e) { /* localStorage/cookie tiltva – nem baj */ }

  form.addEventListener("submit", function (ev) {
    ev.preventDefault();
    err.textContent = "";
    btn.disabled = true;
    fetch("/api/access", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ secret: inp.value }),
    }).then(function (r) {
      if (r.ok) { location.reload(); return; }
      return r.json().catch(function () { return {}; }).then(function (j) {
        err.textContent = (j && j.detail) || "Hibás belépőkód.";
        btn.disabled = false;
        inp.select();
      });
    }).catch(function () {
      err.textContent = "Hálózati hiba.";
      btn.disabled = false;
    });
  });
})();
