"""Durable state for the in-memory registries, on aiosqlite (async SQLite).

What is saved                       how it is detected as changed         notes
  sources                            JSON differs from last flush          the plaintext HTTP token is NEVER written, only its SHA-256
  IOC feeds (manual, misp)           the feed's list object was replaced   demo feeds ("mock*") are not saved; big feeds cost nothing when unchanged
  Merkle batches + open batch        batch id / anchor changed             the batch sequence counter is saved so ids never repeat
  ledger anchors                     new transaction ids                   pruned with their batch (audit-head anchors are kept)
  recent logs, anomalies             (length, newest object) changed       optional (`state_persist_logs`); contents are already PII-redacted

Real-time safety
  * Nothing on the event loop touches the database: snapshots are shallow copies taken synchronously (microseconds),
    JSON serialisation runs in a worker thread (one small dumps per item, so the GIL is released between items), and the SQL
    runs on aiosqlite's own thread. A flush in progress never delays the alerting engine or the pipeline.
  * Writes are one transaction per flush (WAL, synchronous=NORMAL), and change markers advance only after the commit, so a
    failed flush is simply retried on the next tick with nothing lost or half-written.
  * A crash loses at most `flush_interval_s` of state. `close()` does a final flush.
  * Startup never fails because of state: a corrupt file is moved aside and the service starts empty; an unusable path or newer
    schema disables persistence with an error log.
  * Restored batches are re-hashed and compared with their stored Merkle root; a mismatch is logged and left as-is, so the
    existing `/integrity/batches/{id}/audit` endpoint reports it.

Limits: a single process owns the file (no multi-instance sharing); the file holds redacted log content and token hashes, so
protect it like the logs themselves (0600 where the OS supports it) and note it is not encrypted; proofs survive only for the
newest `integrity_max_batches` batches; Drain3 templates and the Isolation Forest are not persisted yet.
"""
import asyncio
import json
import logging
import os
import sqlite3
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

import aiosqlite

from ..integrity.batcher import Batch
from ..integrity.ledger import AnchorReceipt
from ..integrity.merkle import build_tree, hash_record
from ..threatintel.store import IOC

log = logging.getLogger("logunify.state")
SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sources (id TEXT PRIMARY KEY, payload TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS feeds (name TEXT PRIMARY KEY, saved_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS iocs (feed TEXT NOT NULL, type TEXT NOT NULL, value TEXT NOT NULL, category TEXT, threat_level INTEGER,
                                 event_id TEXT, description TEXT, tags TEXT);
CREATE INDEX IF NOT EXISTS iocs_feed ON iocs(feed);
CREATE TABLE IF NOT EXISTS batches (id TEXT PRIMARY KEY, seq INTEGER NOT NULL, anchor_tx TEXT, payload TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS anchors (tx_id TEXT PRIMARY KEY, batch_id TEXT NOT NULL, payload TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS docs (kind TEXT NOT NULL, pos INTEGER NOT NULL, doc TEXT NOT NULL, PRIMARY KEY (kind, pos));
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""


def _dumps(o) -> str:
    return json.dumps(o, separators=(",", ":"), default=str, ensure_ascii=False)


def _copy_deque(d: deque) -> list:
    """list(deque) raises if another thread (a sync API handler) appends mid-copy; retry, it is a microsecond race."""
    for _ in range(8):
        try:
            return list(d)
        except RuntimeError:
            continue
    return []


@dataclass
class _Markers:
    """What is already on disk, so a flush writes only the difference."""
    sources: dict[str, str] = field(default_factory=dict)
    feeds: dict[str, list] = field(default_factory=dict)        # name -> the list object that was written
    batches: dict[str, str | None] = field(default_factory=dict)  # id -> anchor tx id (or None)
    anchors: set[str] = field(default_factory=set)
    docs: dict[str, tuple[int, object]] = field(default_factory=dict)   # kind -> (len, newest object)


class StateStore:
    def __init__(self, path: str, flush_interval_s: float = 5.0, persist_logs: bool = True):
        self.path, self.interval, self.persist_logs = path, max(0.5, flush_interval_s), persist_logs
        self._db: aiosqlite.Connection | None = None
        self._task: asyncio.Task | None = None
        self._lock = asyncio.Lock()
        self._m = _Markers()
        self._c: dict = {}
        self.enabled = False
        self.st = {"flushes": 0, "errors": 0, "last_error": None, "last_flush_at": None, "last_flush_ms": None,
                   "last_rows_written": 0, "loaded": None, "warnings": []}

    # ---- lifecycle ----------------------------------------------------------------------------------------------
    def attach(self, *, sources, ti, batcher, ledger, recent: deque, anomalies: deque) -> "StateStore":
        self._c = dict(sources=sources, ti=ti, batcher=batcher, ledger=ledger, recent=recent, anomalies=anomalies)
        return self

    async def open(self) -> None:
        try:
            if self.path != ":memory:":
                Path(self.path).parent.mkdir(parents=True, exist_ok=True)
            try:
                await self._connect()
            except sqlite3.DatabaseError as e:                           # "file is not a database", malformed image ...
                if self.path == ":memory:":
                    raise
                aside = f"{self.path}.corrupt-{time.strftime('%Y%m%dT%H%M%S')}"
                log.error("state database unreadable (%s); moved to %s and starting empty", e, aside)
                await self._safe_close()
                os.replace(self.path, aside)
                await self._connect()
            self.enabled = True
        except Exception as e:
            log.error("state persistence DISABLED (state stays in memory only): %s", e)
            self.st["last_error"] = f"disabled at startup: {e}"
            await self._safe_close()

    async def _connect(self) -> None:
        self._db = await aiosqlite.connect(self.path)
        if self.path != ":memory:":
            await self._db.execute("PRAGMA journal_mode=WAL")
        await self._db.execute("PRAGMA synchronous=NORMAL")
        await self._db.execute("PRAGMA busy_timeout=5000")
        async with self._db.execute("PRAGMA user_version") as cur:
            ver = (await cur.fetchone())[0]
        if ver > SCHEMA_VERSION:
            raise RuntimeError(f"state file has schema v{ver}, this build understands v{SCHEMA_VERSION}")
        await self._db.executescript(_SCHEMA)
        await self._db.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
        await self._db.commit()
        if self.path != ":memory:":
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass

    async def _safe_close(self) -> None:
        if self._db is not None:
            try:
                await self._db.close()
            except Exception:
                pass
            self._db = None

    def start(self) -> None:
        if self.enabled and self._task is None:
            self._task = asyncio.create_task(self._run(), name="logunify-state-flush")

    async def close(self, final_flush_timeout_s: float = 10.0) -> None:
        if self._task:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
            self._task = None
        if self.enabled:
            try:
                await asyncio.wait_for(self.flush(), final_flush_timeout_s)
            except Exception as e:
                log.error("final state flush failed: %s", e)
        self.enabled = False
        await self._safe_close()

    async def _run(self) -> None:
        while True:
            await asyncio.sleep(self.interval)
            try:
                await self.flush()
            except asyncio.CancelledError:
                raise
            except Exception as e:                                       # never let a DB problem stop the loop
                self.st["errors"] += 1
                self.st["last_error"] = f"{type(e).__name__}: {e}"[:300]
                log.error("state flush failed (will retry in %.0fs): %s", self.interval, e)

    def stats(self) -> dict:
        return {"enabled": self.enabled, "path": self.path, "flush_interval_s": self.interval,
                "persist_logs": self.persist_logs, **self.st}

    # ---- load ----------------------------------------------------------------------------------------------------
    async def load(self) -> dict:
        """Restore saved state into the attached components. Call once, before the pipeline starts."""
        if not self.enabled:
            return {}
        c, db, m = self._c, self._db, self._m
        out: dict = {}
        async with db.execute("SELECT payload FROM sources") as cur:
            rows = [json.loads(r[0]) for r in await cur.fetchall()]
        out["sources"] = c["sources"].restore(rows)
        m.sources = {r["id"]: _dumps(r) for r in rows}

        feeds: dict[str, tuple[list[IOC], str]] = {}
        async with db.execute("SELECT name, saved_at FROM feeds") as cur:
            for name, saved in await cur.fetchall():
                feeds[name] = ([], saved)
        async with db.execute("SELECT feed,type,value,category,threat_level,event_id,description,tags FROM iocs") as cur:
            async for f, t, v, cat, lvl, eid, desc, tags in cur:
                if f in feeds:
                    feeds[f][0].append(IOC(t, v, f, cat or "", lvl, eid or "", desc or "", tuple(json.loads(tags or "[]"))))
        out["iocs"] = c["ti"].restore_feeds(feeds) if c["ti"] else {}
        if c["ti"]:
            m.feeds = {n: l for n, l in c["ti"].store.feeds().items() if n in out["iocs"]}

        receipts: dict[str, AnchorReceipt] = {}
        async with db.execute("SELECT payload FROM anchors") as cur:
            for (p,) in await cur.fetchall():
                r = AnchorReceipt(**json.loads(p))
                receipts[r.tx_id] = r
        c["ledger"].restore(list(receipts.values()))
        m.anchors = set(receipts)

        batches, warnings = [], []
        async with db.execute("SELECT id, seq, anchor_tx, payload FROM batches ORDER BY seq") as cur:
            for bid, seq, tx, p in await cur.fetchall():
                d = json.loads(p)
                b = Batch(bid, seq, d["root"], d["count"], d["leaves"], d["docs"], d["first_ts"], d["last_ts"], d["sealed_at"],
                          receipts.get(tx) if tx else None)
                leaves = [hash_record(x).hex() for x in b.docs]
                if leaves != b.leaves or (build_tree([bytes.fromhex(x) for x in leaves])[-1][0].hex() != b.root if leaves else True):
                    warnings.append(f"{bid}: stored records no longer match the sealed Merkle root (file altered or damaged)")
                batches.append(b)
        async with db.execute("SELECT value FROM meta WHERE key='batch_seq'") as cur:
            row = await cur.fetchone()
        pending = await self._docs("pending")
        c["batcher"].restore(int(row[0]) if row else 0, pending, batches)
        m.batches = {b.id: (b.anchor.tx_id if b.anchor else None) for b in batches}
        out["batches"], out["pending_records"] = len(batches), len(pending)

        if self.persist_logs:
            for kind, dq in (("recent", c["recent"]), ("anomaly", c["anomalies"])):
                docs = await self._docs(kind)
                dq.extend(docs[-dq.maxlen:])
                m.docs[kind] = (len(dq), dq[-1] if dq else None)
            m.docs["pending"] = (len(pending), pending[-1] if pending else None)
            out["recent"], out["anomalies"] = len(c["recent"]), len(c["anomalies"])
        else:
            m.docs["pending"] = (len(pending), pending[-1] if pending else None)
        for w in warnings:
            log.error("INTEGRITY: %s", w)
        self.st["loaded"], self.st["warnings"] = out, warnings
        log.info("state restored: %s", out)
        return out

    async def _docs(self, kind: str) -> list[dict]:
        async with self._db.execute("SELECT doc FROM docs WHERE kind=? ORDER BY pos", (kind,)) as cur:
            return [json.loads(r[0]) for r in await cur.fetchall()]

    # ---- flush ----------------------------------------------------------------------------------------------------
    def _snapshot(self) -> dict:
        """Runs on the event loop: shallow copies only, no I/O, no serialisation."""
        c = self._c
        seq, pending, batches = c["batcher"].snapshot()
        snap = {"sources": c["sources"].snapshot(), "feeds": c["ti"].store.feeds() if c["ti"] else {},
                "seq": seq, "batches": batches, "receipts": c["ledger"].snapshot(),
                "docs": {"pending": pending}}
        if self.persist_logs:
            snap["docs"]["recent"] = _copy_deque(c["recent"])
            snap["docs"]["anomaly"] = _copy_deque(c["anomalies"])
        return snap

    def _plan(self, s: dict) -> dict:
        """Runs in a worker thread: decide what changed and serialise it. Pure with respect to the markers."""
        m, plan = self._m, {}
        rows = {r["id"]: _dumps(r) for r in s["sources"]}
        plan["sources"] = ([(i, p) for i, p in rows.items() if m.sources.get(i) != p], [i for i in m.sources if i not in rows], rows)

        feeds = {n: l for n, l in s["feeds"].items() if not n.startswith("mock")}
        changed = {n: l for n, l in feeds.items() if m.feeds.get(n) is not l}
        plan["feeds"] = ({n: [(i.type, i.value, i.category, i.threat_level, i.event_id, i.description, _dumps(list(i.tags)))
                              for i in l] for n, l in changed.items()},
                         [n for n in m.feeds if n not in feeds], feeds)

        cur = {b.id: (b.anchor.tx_id if b.anchor else None) for b in s["batches"]}
        new_b = [b for b in s["batches"] if b.id not in m.batches or m.batches[b.id] != cur[b.id]]
        plan["batches"] = ([(b.id, b.seq, cur[b.id], _dumps({"root": b.root, "count": b.count, "leaves": b.leaves, "docs": b.docs,
                                                            "first_ts": b.first_ts, "last_ts": b.last_ts, "sealed_at": b.sealed_at}))
                            for b in new_b], [i for i in m.batches if i not in cur], cur)
        new_a = [r for r in s["receipts"] if r.tx_id not in m.anchors]
        plan["anchors"] = ([(r.tx_id, r.batch_id, _dumps(r.to_dict())) for r in new_a], {r.tx_id for r in new_a})

        docs = {}
        for kind, lst in s["docs"].items():
            mark = (len(lst), lst[-1] if lst else None)
            old = m.docs.get(kind)
            if old is None or old[0] != mark[0] or old[1] is not mark[1]:
                docs[kind] = ([(kind, i, _dumps(d)) for i, d in enumerate(lst)], mark)
        plan["docs"] = docs
        plan["seq"] = s["seq"]
        return plan

    async def flush(self) -> dict:
        """Write everything that changed since the last flush. Safe to call concurrently (serialised) and at any time."""
        if not self.enabled:
            return {"skipped": "persistence disabled"}
        async with self._lock:
            t0 = time.perf_counter()
            snap = self._snapshot()
            plan = await asyncio.to_thread(self._plan, snap)
            db, written = self._db, 0
            src_rows, src_del, src_all = plan["sources"]
            feed_rows, feed_del, feed_all = plan["feeds"]
            b_rows, b_del, b_all = plan["batches"]
            a_rows, a_new = plan["anchors"]
            try:
                if src_rows:
                    await db.executemany("INSERT OR REPLACE INTO sources(id,payload) VALUES (?,?)", src_rows)
                if src_del:
                    await db.executemany("DELETE FROM sources WHERE id=?", [(i,) for i in src_del])
                now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                for name, rows in feed_rows.items():
                    await db.execute("DELETE FROM iocs WHERE feed=?", (name,))
                    await db.executemany("INSERT INTO iocs(feed,type,value,category,threat_level,event_id,description,tags) "
                                         "VALUES (?,?,?,?,?,?,?,?)", [(name, *r) for r in rows])
                    await db.execute("INSERT OR REPLACE INTO feeds(name,saved_at) VALUES (?,?)", (name, now))
                    written += len(rows)
                for name in feed_del:
                    await db.execute("DELETE FROM iocs WHERE feed=?", (name,))
                    await db.execute("DELETE FROM feeds WHERE name=?", (name,))
                if b_rows:
                    await db.executemany("INSERT OR REPLACE INTO batches(id,seq,anchor_tx,payload) VALUES (?,?,?,?)", b_rows)
                if b_del:
                    await db.executemany("DELETE FROM batches WHERE id=?", [(i,) for i in b_del])
                if a_rows:
                    await db.executemany("INSERT OR REPLACE INTO anchors(tx_id,batch_id,payload) VALUES (?,?,?)", a_rows)
                await db.execute("DELETE FROM anchors WHERE batch_id LIKE 'batch-%' AND batch_id NOT IN (SELECT id FROM batches)")
                for kind, (rows, _mark) in plan["docs"].items():
                    await db.execute("DELETE FROM docs WHERE kind=?", (kind,))
                    await db.executemany("INSERT INTO docs(kind,pos,doc) VALUES (?,?,?)", rows)
                    written += len(rows)
                await db.execute("INSERT OR REPLACE INTO meta(key,value) VALUES ('batch_seq',?)", (str(plan["seq"]),))
                await db.commit()
            except BaseException:
                await db.rollback()                                       # markers untouched: the next flush redoes it all
                raise
            m = self._m                                                    # commit succeeded: advance the markers
            m.sources = src_all
            m.feeds = {n: feed_all[n] for n in feed_all}
            m.batches = b_all
            m.anchors |= a_new
            for kind, (_rows, mark) in plan["docs"].items():
                m.docs[kind] = mark
            written += len(src_rows) + len(b_rows) + len(a_rows)
            self.st.update(flushes=self.st["flushes"] + 1, last_flush_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                           last_flush_ms=round((time.perf_counter() - t0) * 1000, 1), last_rows_written=written, last_error=None)
            return {"rows_written": written, "ms": self.st["last_flush_ms"]}
