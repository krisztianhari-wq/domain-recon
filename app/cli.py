"""Üzemeltetői/parancssori felület: egy domain feltérképezése a webszerver nélkül.

  python -m app.cli scan example.com [--ports service|common|full|custom] [--custom 22,80,443]
                                     [--intensity polite|normal|aggressive] [--wordlist] [--no-ports] [--private] [--json]
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys

from .engine import Engine


class _MemDB:
    """Memóriabeli ál-DB a CLI-hez (nem ír lemezre)."""
    def __init__(self):
        self._h: dict[str, dict] = {}
        self.meta: dict = {}

    def set_status(self, *_a, **_k): pass
    def set_progress(self, _id, stage, done, total):
        print(f"\r  {stage}: {done}/{total}   ", end="", file=sys.stderr, flush=True)
    def set_counts(self, _id, nh, nl, npq): self.meta.update(n_hosts=nh, n_live=nl, n_ports=npq)
    def upsert_host(self, _id, host, data): self._h[host] = data
    def hosts(self, _id): return [{**d, "host": h} for h, d in sorted(self._h.items())]


async def _run(args):
    db = _MemDB()
    opts = {
        "ports": args.ports, "custom_ports": args.custom or "", "intensity": args.intensity,
        "ct": not args.no_ct, "wordlist": args.wordlist, "scan_ports": not args.no_ports,
        "allow_private": args.private,
    }
    eng = Engine(db, "cli", args.domain, opts)
    await eng.run()
    print("", file=sys.stderr)
    rows = db.hosts("cli")
    if args.json:
        print(json.dumps({"domain": eng.domain, **db.meta, "hosts": rows}, ensure_ascii=False, indent=2))
        return
    for h in rows:
        live = "LIVE" if h.get("alive") else "dead"
        ips = ",".join(h.get("ips", [])) or "-"
        ports = " ".join(f"{p['port']}/{p.get('name','?')}" for p in h.get("ports", [])) or "-"
        print(f"{h['host']:<45} {live:<5} {ips:<40} {ports}")
    print(f"\n# {db.meta.get('n_hosts',0)} host · {db.meta.get('n_live',0)} élő · {db.meta.get('n_ports',0)} nyitott port", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(prog="domain-recon")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="domain feltérképezése")
    s.add_argument("domain")
    s.add_argument("--ports", default="service", choices=["service", "common", "full", "custom"])
    s.add_argument("--custom", default="")
    s.add_argument("--intensity", default="polite", choices=["polite", "normal", "aggressive"])
    s.add_argument("--wordlist", action="store_true")
    s.add_argument("--no-ct", action="store_true", help="CT-napló kikapcsolása")
    s.add_argument("--no-ports", action="store_true", help="csak felsorolás+DNS, portscan nélkül")
    s.add_argument("--private", action="store_true", help="privát IP-ket is szkennel")
    s.add_argument("--json", action="store_true")
    args = ap.parse_args()
    asyncio.run(_run(args))


if __name__ == "__main__":
    main()
