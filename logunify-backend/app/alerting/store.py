"""SQLite persistence for alerts and their audit trail.

Why durable: the CERT-In clock must survive a restart, and the record of who was told what, when, and who reported
it is compliance evidence. The events table is append-only (enforced with triggers) and every state change writes
an event in the same transaction as the alert row. File-level tampering is out of scope: back the file up to WORM
storage if you need that.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading

from .models import Alert

_SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY, status TEXT NOT NULL, created_at REAL NOT NULL, due_at REAL NOT NULL,
    dedup_key TEXT NOT NULL, data TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_alerts_status ON alerts(status);
CREATE TABLE IF NOT EXISTS events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT, alert_id TEXT NOT NULL, at REAL NOT NULL,
    actor TEXT NOT NULL, kind TEXT NOT NULL, data TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_events_alert ON events(alert_id);
CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events
    BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events
    BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
"""


class AlertStore:
    def __init__(self, path: str = ":memory:"):
        self.path = path
        self._lock = threading.RLock()
        self._conn: sqlite3.Connection | None = None

    def exists(self) -> bool:
        return self._conn is not None or self.path == ":memory:" or os.path.exists(self.path)

    def _db(self) -> sqlite3.Connection:
        if self._conn is None:                                   # lazy: nothing is created until the first alert
            if self.path != ":memory:":
                os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
            conn = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=FULL")
            conn.executescript(_SCHEMA)
            if self.path != ":memory:":
                try:
                    os.chmod(self.path, 0o600)                   # alerts contain incident evidence; no-op on Windows
                except OSError:
                    pass
            self._conn = conn
        return self._conn

    def save(self, alert: Alert, event: tuple[str, str, dict, float] | None = None) -> None:
        """Upsert the alert and (optionally) append an audit event, atomically. event = (kind, actor, data, at)."""
        with self._lock:
            db = self._db()
            db.execute("BEGIN IMMEDIATE")
            try:
                db.execute(
                    "INSERT INTO alerts(id, status, created_at, due_at, dedup_key, data) VALUES(?,?,?,?,?,?) "
                    "ON CONFLICT(id) DO UPDATE SET status=excluded.status, data=excluded.data",
                    (alert.id, alert.status, alert.created_at, alert.due_at, alert.dedup_key, alert.to_json()))
                if event:
                    kind, actor, data, at = event
                    db.execute("INSERT INTO events(alert_id, at, actor, kind, data) VALUES(?,?,?,?,?)",
                               (alert.id, at, actor, kind, json.dumps(data, default=str)))
                db.execute("COMMIT")
            except Exception:
                db.execute("ROLLBACK")
                raise

    def add_event(self, alert_id: str, kind: str, actor: str, data: dict, at: float) -> None:
        with self._lock:
            self._db().execute("INSERT INTO events(alert_id, at, actor, kind, data) VALUES(?,?,?,?,?)",
                               (alert_id, at, actor, kind, json.dumps(data, default=str)))

    def get(self, alert_id: str) -> Alert | None:
        if not self.exists():
            return None
        with self._lock:
            row = self._db().execute("SELECT data FROM alerts WHERE id=?", (alert_id,)).fetchone()
        return Alert.from_json(row[0]) if row else None

    def load(self, statuses: tuple[str, ...]) -> list[Alert]:
        if not self.exists():
            return []
        marks = ",".join("?" * len(statuses))
        with self._lock:
            rows = self._db().execute(f"SELECT data FROM alerts WHERE status IN ({marks}) ORDER BY created_at", statuses).fetchall()
        return [Alert.from_json(r[0]) for r in rows]

    def list_alerts(self, status: str | None = None, limit: int = 100) -> list[Alert]:
        if not self.exists():
            return []
        q, args = "SELECT data FROM alerts", []
        if status:
            q += " WHERE status=?"
            args.append(status)
        with self._lock:
            rows = self._db().execute(q + " ORDER BY created_at DESC LIMIT ?", (*args, limit)).fetchall()
        return [Alert.from_json(r[0]) for r in rows]

    def events(self, alert_id: str) -> list[dict]:
        if not self.exists():
            return []
        with self._lock:
            rows = self._db().execute("SELECT seq, at, actor, kind, data FROM events WHERE alert_id=? ORDER BY seq",
                                      (alert_id,)).fetchall()
        return [{"seq": s, "at": at, "actor": actor, "kind": kind, "data": json.loads(d)} for s, at, actor, kind, d in rows]

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None
