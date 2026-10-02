"""SQLite tár: vizsgálatok (scans) és eredmény-hostok (results). WAL, egyszálú íróval.

Egy scan = egy domain feltérképezése adott opciókkal. A hostok JSON-ként tárolódnak
(IP-k, DNS, nyitott portok ujjlenyomattal) – a listázás/él-nézet olvasó.
"""
from __future__ import annotations

import json
import os
import sqlite3
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans(
  id        TEXT PRIMARY KEY,
  domain    TEXT NOT NULL,
  opts      TEXT NOT NULL,
  status    TEXT NOT NULL,          -- (passzív) queued|running|done|error|canceled
  stage     TEXT,
  note      TEXT,                   -- nem-fatális figyelmeztetés (pl. host-korlát miatti csonkolás)
  done      INTEGER DEFAULT 0,
  total     INTEGER DEFAULT 0,
  error     TEXT,
  active_status TEXT DEFAULT 'none', -- none|queued|running|done|error|canceled
  active_stage  TEXT,
  active_done   INTEGER DEFAULT 0,
  active_total  INTEGER DEFAULT 0,
  posture   TEXT,                   -- JSON: apex DNS-posture (MX/NS/SPF/DMARC/CAA/DKIM)
  wildcard  TEXT,                   -- JSON: wildcard-IP-k
  n_hosts   INTEGER DEFAULT 0,
  n_live    INTEGER DEFAULT 0,
  n_ports   INTEGER DEFAULT 0,
  created   INTEGER NOT NULL,
  started   INTEGER,
  finished  INTEGER
);
CREATE TABLE IF NOT EXISTS results(
  scan_id   TEXT NOT NULL,
  host      TEXT NOT NULL,
  data      TEXT NOT NULL,          -- JSON: {ips, dns, alive, source, ports:[...], ...}
  PRIMARY KEY (scan_id, host)
);
CREATE INDEX IF NOT EXISTS results_scan ON results(scan_id);
"""


class DB:
    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self._cx = sqlite3.connect(path, check_same_thread=False)
        self._cx.row_factory = sqlite3.Row
        self._cx.execute("PRAGMA journal_mode=WAL")
        self._cx.execute("PRAGMA synchronous=NORMAL")
        self._cx.execute("PRAGMA busy_timeout=5000")
        self._cx.executescript(SCHEMA)
        self._cx.commit()

    # ---- scans ----
    def create_scan(self, scan_id: str, domain: str, opts: dict) -> None:
        self._cx.execute(
            "INSERT INTO scans(id,domain,opts,status,stage,created) VALUES(?,?,?,?,?,?)",
            (scan_id, domain, json.dumps(opts), "queued", "queued", int(time.time())),
        )
        self._cx.commit()

    _STATUS_COLS = {"stage", "done", "total", "error", "n_hosts", "n_live", "n_ports", "started", "finished",
                    "note", "active_status", "active_stage", "active_done", "active_total"}

    def set_status(self, scan_id: str, status: str, **fields) -> None:
        cols, vals = ["status"], [status]
        if status == "running" and "started" not in fields:
            fields["started"] = int(time.time())
        if status in ("done", "error", "canceled"):
            fields["finished"] = int(time.time())
        for k, v in fields.items():
            if k not in self._STATUS_COLS:            # fehérlista: csak ismert oszlopnév kerülhet a SQL-be
                raise ValueError(f"ismeretlen oszlop: {k}")
            cols.append(k)
            vals.append(v)
        vals.append(scan_id)
        self._cx.execute(f"UPDATE scans SET {','.join(c+'=?' for c in cols)} WHERE id=?", vals)
        self._cx.commit()

    def set_note(self, scan_id: str, note: str) -> None:
        self._cx.execute("UPDATE scans SET note=? WHERE id=?", (note, scan_id))
        self._cx.commit()

    def set_progress(self, scan_id: str, stage: str, done: int, total: int) -> None:
        self._cx.execute("UPDATE scans SET stage=?,done=?,total=? WHERE id=?", (stage, done, total, scan_id))
        self._cx.commit()

    def set_active_progress(self, scan_id: str, stage: str, done: int, total: int) -> None:
        self._cx.execute("UPDATE scans SET active_stage=?,active_done=?,active_total=? WHERE id=?",
                         (stage, done, total, scan_id))
        self._cx.commit()

    def set_posture(self, scan_id: str, posture: dict) -> None:
        self._cx.execute("UPDATE scans SET posture=? WHERE id=?", (json.dumps(posture), scan_id))
        self._cx.commit()

    def set_wildcard(self, scan_id: str, ips: list) -> None:
        self._cx.execute("UPDATE scans SET wildcard=? WHERE id=?", (json.dumps(ips), scan_id))
        self._cx.commit()

    def set_counts(self, scan_id: str, n_hosts: int, n_live: int, n_ports: int) -> None:
        self._cx.execute("UPDATE scans SET n_hosts=?,n_live=?,n_ports=? WHERE id=?",
                         (n_hosts, n_live, n_ports, scan_id))
        self._cx.commit()

    def get_scan(self, scan_id: str) -> dict | None:
        r = self._cx.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not r:
            return None
        d = dict(r)
        d["opts"] = json.loads(d["opts"])
        d["posture"] = json.loads(d["posture"]) if d.get("posture") else None
        d["wildcard"] = json.loads(d["wildcard"]) if d.get("wildcard") else []
        return d

    def recent_scans(self, limit: int = 40) -> list[dict]:
        rows = self._cx.execute(
            "SELECT id,domain,status,active_status,n_hosts,n_live,n_ports,created,finished FROM scans "
            "ORDER BY created DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def delete_scan(self, scan_id: str) -> None:
        self._cx.execute("DELETE FROM results WHERE scan_id=?", (scan_id,))
        self._cx.execute("DELETE FROM scans WHERE id=?", (scan_id,))
        self._cx.commit()

    def prune(self, keep: int = 60) -> None:
        """Legfeljebb `keep` scan marad; a régebbiek (eredményestül) törlődnek."""
        old = self._cx.execute(
            "SELECT id FROM scans ORDER BY created DESC LIMIT -1 OFFSET ?", (keep,)).fetchall()
        for r in old:
            self.delete_scan(r["id"])

    # ---- results ----
    def upsert_host(self, scan_id: str, host: str, data: dict) -> None:
        self._cx.execute(
            "INSERT INTO results(scan_id,host,data) VALUES(?,?,?) "
            "ON CONFLICT(scan_id,host) DO UPDATE SET data=excluded.data",
            (scan_id, host, json.dumps(data)))
        self._cx.commit()

    def hosts(self, scan_id: str) -> list[dict]:
        rows = self._cx.execute("SELECT host,data FROM results WHERE scan_id=? ORDER BY host", (scan_id,)).fetchall()
        out = []
        for r in rows:
            d = json.loads(r["data"])
            d["host"] = r["host"]
            out.append(d)
        return out

    def close(self) -> None:
        try:
            self._cx.close()
        except Exception:  # noqa: BLE001
            pass
