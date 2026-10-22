// Nyomtatható jelentés – a gomb a böngésző nyomtatás/PDF párbeszédét nyitja. Szövegek a szerverről jönnek.
"use strict";
document.addEventListener("DOMContentLoaded", () => {
  const b = document.getElementById("print");
  if (b) b.addEventListener("click", () => window.print());
});
