"""Tamper-evident audit log of analyst / admin actions.

Every record stores `prev_hash` and `hash = H(prev_hash || canonical(record))`, where H is HMAC-SHA256 when
LOGUNIFY_AUDIT_HMAC_KEY is set (then an attacker with database write access cannot recompute the chain) and plain SHA-256
otherwise (detects accidental damage and naive edits only; a DB-level attacker can rebuild it). SQLite triggers abort
UPDATE and DELETE. `verify()` finds edited or removed records in the middle of the chain.

Limits: truncating the newest records is undetectable from inside the chain. Witness `head()` externally (`/audit/head`,
or anchor it on the ledger via `/audit/anchor`, which is a MOCK ledger today) and pass it back as `expected_head`.
The log records the authorised ATTEMPT of an action; it does not know whether the action then succeeded.
Never put secrets in `detail`: it is passed through `redact()` and size-capped.
"""
import hashlib
import hmac
import json
import sqlite3
import threading
import time
from pathlib import Path

from ..alerting.redact import redact

GENESIS = "0" * 64
_COLS = ("seq", "ts", "actor", "role", "auth", "action", "resource", "outcome", "client", "detail")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, actor TEXT NOT NULL, role TEXT NOT NULL, auth TEXT NOT NULL,
  action TEXT NOT NULL, resource TEXT NOT NULL, outcome TEXT NOT NULL, client TEXT, detail TEXT NOT NULL,
  prev_hash TEXT NOT NULL, hash TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
"""


class AuditLog:
    def __init__(self, path: str = "data/audit.db", hmac_key: str | None = None):
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.executescript(_SCHEMA)
        self._lock = threading.Lock()
        self._key = hmac_key.encode() if hmac_key else None
        self.keyed = self._key is not None
        self._last: dict[tuple, list] = {}            # (actor, action) -> [last_write_ts, suppressed_count]

    def _digest(self, prev: str, rec: dict) -> str:
        msg = (prev + json.dumps(rec, sort_keys=True, separators=(",", ":"), ensure_ascii=False)).encode()
        return hmac.new(self._key, msg, hashlib.sha256).hexdigest() if self._key else hashlib.sha256(msg).hexdigest()

    def append(self, actor: str, role: str, auth: str, action: str, resource: str, outcome: str = "allowed",
               client: str | None = None, detail: dict | None = None, sample_s: float = 0) -> int | None:
        """Append one record; returns its seq. With sample_s>0, repeats of the same (actor, action) inside the window are
        counted and folded into the next record's `coalesced` field (used for polled read endpoints)."""
        now = time.time()
        detail = dict(detail or {})
        with self._lock:
            if sample_s > 0 and outcome == "allowed":
                st = self._last.setdefault((actor, action), [0.0, 0])
                if now - st[0] < sample_s:
                    st[1] += 1
                    return None
                if st[1]:
                    detail["coalesced"] = st[1]
                st[0], st[1] = now, 0
            blob = redact(json.dumps(detail, default=str, sort_keys=True), 2000)
            row = self._db.execute("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
            prev = row[0] if row else GENESIS
            seq = (self._db.execute("SELECT COALESCE(MAX(seq),0) FROM audit").fetchone()[0]) + 1
            rec = dict(zip(_COLS, (seq, round(now, 6), actor[:120], role, auth, action, resource[:300], outcome,
                                   client, blob)))
            self._db.execute(
                "INSERT INTO audit (seq,ts,actor,role,auth,action,resource,outcome,client,detail,prev_hash,hash) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", (*rec.values(), prev, self._digest(prev, rec)))
            self._db.commit()
            return seq

    def _rows(self, where: str = "", args: tuple = (), tail: str = "ORDER BY seq"):
        cur = self._db.execute(f"SELECT {','.join(_COLS)},prev_hash,hash FROM audit {where} {tail}", args)
        return [dict(zip((*_COLS, "prev_hash", "hash"), r)) for r in cur.fetchall()]

    def list(self, limit: int = 100, actor: str | None = None, action: str | None = None,
             before_seq: int | None = None) -> list[dict]:
        cond, args = [], []
        for col, val in (("actor", actor), ("action", action)):
            if val:
                cond.append(f"{col}=?")
                args.append(val)
        if before_seq:
            cond.append("seq<?")
            args.append(before_seq)
        with self._lock:
            rows = self._rows("WHERE " + " AND ".join(cond) if cond else "", tuple(args),
                              f"ORDER BY seq DESC LIMIT {int(limit)}")
        for r in rows:
            try:
                r["detail"] = json.loads(r["detail"])
            except ValueError:                        # truncated by the size cap
                r["detail"] = {"truncated": r["detail"]}
        return rows

    def head(self) -> dict:
        with self._lock:
            row = self._db.execute("SELECT seq,hash,ts FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        return {"seq": row[0], "hash": row[1], "ts": row[2], "keyed": self.keyed} if row else \
               {"seq": 0, "hash": GENESIS, "ts": None, "keyed": self.keyed}

    def verify(self, expected_head: dict | None = None) -> dict:
        """Recompute the whole chain. `expected_head` ({seq, hash} witnessed earlier) also catches tail truncation."""
        with self._lock:
            rows = self._rows()
        prev, expect_seq = GENESIS, 1
        for r in rows:
            rec = {c: r[c] for c in _COLS}
            if r["seq"] != expect_seq:
                return {"valid": False, "records": len(rows), "broken_at": expect_seq,
                        "reason": "missing record(s): sequence gap"}
            if r["prev_hash"] != prev or r["hash"] != self._digest(prev, rec):
                return {"valid": False, "records": len(rows), "broken_at": r["seq"],
                        "reason": "record content or link does not match its hash"}
            prev, expect_seq = r["hash"], expect_seq + 1
        out = {"valid": True, "records": len(rows), "broken_at": None, "head_hash": prev, "keyed": self.keyed}
        if expected_head:
            hit = next((r for r in rows if r["seq"] == expected_head.get("seq")), None)
            if hit is None or hit["hash"] != expected_head.get("hash"):
                out.update(valid=False, reason="witnessed head not found in chain: log truncated or rewritten")
        return out
