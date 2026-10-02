#!/usr/bin/env bash
# Önálló macOS .app építése PyInstallerrel. Helyben és CI-ben is fut.
# Használat: ./build-mac.sh     (eredmény: dist/domain-recon.app)
set -euo pipefail
cd "$(dirname "$0")"
PY=${PYTHON:-python3}
$PY -m pip install -q -r requirements.txt pyinstaller
NAME="domain-recon"
ARGS=(--noconfirm --clean --name "$NAME" --windowed
      --collect-all uvicorn --collect-submodules uvicorn
      --collect-submodules fastapi --collect-submodules starlette
      --collect-all anyio --collect-submodules httpx --collect-submodules httpcore
      --collect-all pydantic --collect-all pydantic_core
      --add-data "app/static:app/static"
      --hidden-import app.main --hidden-import app.engine --hidden-import app.fingerprint
      --hidden-import app.ports --hidden-import app.db --hidden-import app.netchecks
      --hidden-import uvicorn.loops.auto --hidden-import uvicorn.protocols.http.auto
      --hidden-import uvicorn.protocols.websockets.auto --hidden-import uvicorn.lifespan.on)
case "$(uname -s)" in
  Darwin) ARGS+=(--osx-bundle-identifier hu.sadrobot.domainrecon) ;;
esac
$PY -m PyInstaller "${ARGS[@]}" launcher.py
echo "--- kész ---"
ls -la dist
