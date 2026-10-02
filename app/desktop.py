"""Asztali indító: a domain-recon helyben, saját adatkönyvtárral, böngészőablakban.

A Mac-es `.app` (PyInstaller, --windowed) és a `run-mac.command` is ezt hívja. A szerver csak a
127.0.0.1-re köt, proxy-titok és Host-szűrés nélkül (egyfelhasználós, helyi mérőpont).
"""
from __future__ import annotations

import argparse
import os
import socket
import sys
import threading
import webbrowser


def _free_port(preferred: int = 8795) -> int:
    for p in (preferred, 0):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("127.0.0.1", p))
                return s.getsockname()[1]
        except OSError:
            continue
    return preferred


def _data_dir() -> str:
    if sys.platform == "darwin":
        base = os.path.expanduser("~/Library/Application Support/domain-recon")
    elif os.name == "nt":
        base = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "domain-recon")
    else:
        base = os.path.join(os.environ.get("XDG_DATA_HOME", os.path.expanduser("~/.local/share")), "domain-recon")
    os.makedirs(base, exist_ok=True)
    return base


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="domain-recon", description="Helyi domain-feltérképező (sadrobot)")
    ap.add_argument("--port", type=int, default=8795)
    ap.add_argument("--no-browser", action="store_true")
    ap.add_argument("--server-only", action="store_true", help="csak a szerver (nem nyit böngészőt)")
    a = ap.parse_args(argv)

    # a helyi mód mindig 127.0.0.1-re köt, proxy-titok és Host-szűrés nélkül – ezt az app.main importja előtt rögzítjük
    os.environ.setdefault("RECON_DATA", _data_dir())
    os.environ.pop("RECON_PROXY_SECRET", None)
    os.environ.pop("RECON_ALLOWED_HOSTS", None)

    port = _free_port(a.port)
    import uvicorn  # késleltetett import: az env már be van állítva
    from app.main import app

    url = f"http://127.0.0.1:{port}/"
    if not (a.no_browser or a.server_only):
        threading.Timer(0.9, lambda: webbrowser.open(url)).start()
    print(f"domain-recon → {url}  (adat: {os.environ['RECON_DATA']})", flush=True)
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")
    return 0


if __name__ == "__main__":
    import multiprocessing
    multiprocessing.freeze_support()
    sys.exit(main())
