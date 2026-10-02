"""Parancssori felület: egy domain feltérképezése webszerver nélkül.

  python -m app.cli scan example.com                      # csak passzív (alap)
  python -m app.cli scan example.com --active             # passzív + aktív (portscan, ujjlenyomat)
  python -m app.cli scan example.com --active --ports full --intensity normal --brute --json
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
        self.meta: dict = {"n_hosts": 0, "n_live": 0, "n_ports": 0, "wildcard": [], "posture": None,
                           "opts": {}, "domain": ""}

    def set_status(self, *_a, **_k): pass
    def set_note(self, _id, note): print(f"  note: {note}", file=sys.stderr)
    def set_progress(self, _id, stage, done, total):
        print(f"\r  [passzív] {stage}: {done}/{total}   ", end="", file=sys.stderr, flush=True)
    def set_active_progress(self, _id, stage, done, total):
        print(f"\r  [aktív] {stage}: {done}/{total}   ", end="", file=sys.stderr, flush=True)
    def set_counts(self, _id, nh, nl, npq): self.meta.update(n_hosts=nh, n_live=nl, n_ports=npq)
    def set_posture(self, _id, p): self.meta["posture"] = p
    def set_wildcard(self, _id, ips): self.meta["wildcard"] = ips
    def upsert_host(self, _id, host, data): self._h[host] = {k: v for k, v in data.items() if k != "host"}
    def hosts(self, _id): return [{**d, "host": h} for h, d in sorted(self._h.items())]
    def get_scan(self, _id): return {**self.meta, "wildcard": self.meta["wildcard"]}


async def _run(args):
    db = _MemDB()
    opts = {"ports": args.ports, "custom_ports": args.custom or "", "intensity": args.intensity,
            "scan_ports": not args.no_ports, "brute": args.brute, "allow_private": args.private}
    db.meta["opts"] = opts
    db.meta["domain"] = args.domain
    eng = Engine(db, "cli", args.domain, opts)
    await eng.run_passive()
    print("", file=sys.stderr)
    if args.active:
        await eng.run_active()
        print("", file=sys.stderr)

    rows = db.hosts("cli")
    if args.json:
        print(json.dumps({"domain": eng.domain, **db.meta, "hosts": rows}, ensure_ascii=False, indent=2))
        return
    for h in rows:
        live = "LIVE" if h.get("alive") else "dead"
        ips = ",".join(h.get("ips", [])) or "-"
        extra = []
        if h.get("cname"):
            extra.append(f"CNAME={h['cname']}")
        if h.get("takeover"):
            extra.append(f"TAKEOVER?={h['takeover']['service']}")
        ports = " ".join(f"{p['port']}/{p.get('name','?')}" for p in h.get("ports", [])) or ""
        if ports:
            extra.append(ports)
        print(f"{h['host']:<45} {live:<5} {ips:<40} {' '.join(extra)}")
    po = db.meta.get("posture") or {}
    print(f"\n# {db.meta['n_hosts']} host · {db.meta['n_live']} élő · {db.meta['n_ports']} port"
          f" · SPF:{'ok' if po.get('spf_ok') else 'nincs'} DMARC:{'ok' if po.get('dmarc_ok') else 'nincs'}"
          f" · wildcard:{len(db.meta.get('wildcard') or [])}", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(prog="domain-recon")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="domain feltérképezése")
    s.add_argument("domain")
    s.add_argument("--active", action="store_true", help="aktív fázis is (portscan, ujjlenyomat)")
    s.add_argument("--ports", default="service", choices=["service", "common", "full", "custom"])
    s.add_argument("--custom", default="")
    s.add_argument("--intensity", default="polite", choices=["polite", "normal", "aggressive"])
    s.add_argument("--brute", action="store_true", help="DNS-brute a gyakori prefixekkel (aktív)")
    s.add_argument("--no-ports", action="store_true", help="aktívban portscan nélkül")
    s.add_argument("--private", action="store_true", help="privát IP-ket is szkennel")
    s.add_argument("--json", action="store_true")
    args = ap.parse_args()
    asyncio.run(_run(args))


if __name__ == "__main__":
    main()
