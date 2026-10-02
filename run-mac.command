#!/usr/bin/env bash
# domain-recon – helyi futtatás építés nélkül (dupla kattintás a Finderben).
# Első indításkor létrehoz egy virtuális környezetet és telepíti a függőségeket, majd böngészőt nyit.
set -euo pipefail
cd "$(dirname "$0")"
PY="$(command -v python3.12 || command -v python3 || true)"
[ -n "$PY" ] || { echo "Nincs python3 a gépen. Telepítsd: https://www.python.org/downloads/"; read -r _; exit 1; }
if [ ! -d .venv ]; then
  echo "Első indítás: virtuális környezet létrehozása…"
  "$PY" -m venv .venv
  .venv/bin/pip install -q --upgrade pip
  .venv/bin/pip install -q -r requirements.txt
fi
echo "domain-recon indítása…  (a böngésző magától megnyílik; leállítás: Ctrl+C)"
exec .venv/bin/python -m app.desktop
