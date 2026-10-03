#!/usr/bin/env bash
# Cross-platform standalone build with PyInstaller. Runs locally and in CI.
#   macOS   -> dist/domain-recon.app   (icon: assets/icon.icns)
#   Windows -> dist/domain-recon/      (domain-recon.exe, icon: assets/icon.ico)
#   Linux   -> dist/domain-recon/
# Usage: ./build.sh
set -euo pipefail
cd "$(dirname "$0")"
PY=${PYTHON:-python3}
command -v "$PY" >/dev/null 2>&1 || PY=python
"$PY" -m pip install -q -r requirements.txt pyinstaller
NAME="domain-recon"

case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) SEP=";" ;;   # Windows (git-bash): PyInstaller --add-data uses ';'
  *)                    SEP=":" ;;
esac

ARGS=(--noconfirm --clean --name "$NAME" --windowed
      --collect-all uvicorn --collect-submodules uvicorn
      --collect-submodules fastapi --collect-submodules starlette
      --collect-all anyio --collect-submodules httpx --collect-submodules httpcore
      --collect-all pydantic --collect-all pydantic_core
      --collect-all openpyxl
      --add-data "app/static${SEP}app/static"
      --hidden-import app.main --hidden-import app.engine --hidden-import app.fingerprint
      --hidden-import app.ports --hidden-import app.db --hidden-import app.netchecks
      --hidden-import app.sources --hidden-import app.enrich --hidden-import app.vulncheck
      --hidden-import uvicorn.loops.auto --hidden-import uvicorn.protocols.http.auto
      --hidden-import uvicorn.protocols.websockets.auto --hidden-import uvicorn.lifespan.on)

case "$(uname -s)" in
  Darwin)               ARGS+=(--icon assets/icon.icns --osx-bundle-identifier hu.sadrobot.domainrecon) ;;
  MINGW*|MSYS*|CYGWIN*) ARGS+=(--icon assets/icon.ico) ;;
esac

"$PY" -m PyInstaller "${ARGS[@]}" launcher.py
echo "--- done ---"
ls -la dist
