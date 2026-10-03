# Durable state (`app/state/store.py`; SQLite or PostgreSQL)

Saved to `LOGUNIFY_STATE_DB_PATH` (default `data/state.db`) and reloaded at startup, before the pipeline, threat-intel sync or any
listener starts:

| state | notes |
|---|---|
| event sources | the plaintext HTTP token is **never** written: only its SHA-256 (ingest compares hashes), so a restored source keeps working with the token it was issued. Syslog sources re-bind their ports |
| IOC feeds `manual`, `misp` | demo feeds (`mock*`) are not saved; a saved `misp` feed is restored only if MISP is still configured (otherwise nothing could refresh it) |
| Merkle batches, open batch, batch sequence, ledger anchors | ids never repeat after a restart; proofs and anchors survive; restored batches are re-hashed and a mismatch with the sealed root is logged and shown by `/integrity/batches/{id}/audit` |
| recent logs, anomalies | optional (`LOGUNIFY_STATE_PERSIST_LOGS`); already PII-redacted. The recent-events log is saved **incrementally** (only events newer than the last flush are written, rows older than the buffer are pruned), so a 50,000-event buffer costs the same per flush as a small one; anomalies (200) are rewritten whole |

| learned models | Drain3 templates (snapshot) and the Isolation Forest training window (feature vectors, JSON). Saved at most every `LOGUNIFY_STATE_MODEL_INTERVAL_S` (60 s) and on shutdown; after a restart templates keep their ids and the forest is refitted from the window, so scoring is live immediately instead of after the warm-up. **Needs an HMAC key** (below) |

## PostgreSQL backend (shared server, one schema per replica)
`LOGUNIFY_STATE_DATABASE_URL=postgresql://user:pass@host:5432/logunify` switches the same store from a SQLite file to PostgreSQL
(`asyncpg`, one connection, same transaction-per-flush design). Each replica gets its own schema `logunify_<worker id>`, created on
first start, so replicas keep the ownership model of the per-replica files but share one server: one backup (`pg_dump`), one place to
monitor, no per-replica volume. A session advisory lock on the schema makes a second process with the same `LOGUNIFY_WORKER_ID` fail fast
(persistence disabled, error logged, service keeps running) instead of overwriting the first. A lost connection is re-opened on the next flush;
a failed flush is rolled back and redone in full. Use TLS (`?sslmode=verify-full`) and a role that owns only its schemas.

**What this is not:** logical sharing. Sources, IOC feeds and Merkle batches are still owned by the replica that created them; a source added
through replica A is not visible on B until B restarts into the same schema. True multi-writer state (one global source registry, one batch
sequence) is not implemented. SQLite remains the default and is unchanged apart from the `models` table (v1 files upgrade in place).

## Model blobs are signed
Drain3 snapshots are jsonpickle, and unpickling attacker-supplied data is code execution. Every saved model blob is stored with an
HMAC-SHA256 (`LOGUNIFY_STATE_HMAC_KEY`, else `LOGUNIFY_AUDIT_HMAC_KEY`) and verified **before** anything is parsed; a blob that fails is ignored
with a warning in `GET /api/v1/state` and that model re-learns. No key = models are not persisted (also warned). The Isolation Forest is never
pickled: only its feature vectors are stored. Rotating the key discards the saved models once.

## Redis (request-rate limit)
`LOGUNIFY_REDIS_URL` makes `LOGUNIFY_RATE_LIMIT_PER_MIN` one limit across all replicas (fixed window, `INCR`+`EXPIRE`). Redis calls time out at
0.5 s and any error falls back to the per-replica limiter (logged once a minute), so Redis can never take the API down; the cost is that the
limit is then per replica. Not moved to Redis yet: the brute-force lockout (`FailureLimiter`), token revocations, alert/audit stores (still
SQLite per replica / shared file).

## How it stays out of the real-time path
Snapshots are shallow copies on the event loop (microseconds); JSON serialisation runs in a worker thread, item by item; SQL runs on
aiosqlite's thread. Only what changed since the last flush is written (unchanged state: 0 rows, ~2 ms). One transaction per flush (WAL);
change markers advance only after the commit, so a failed flush is retried in full. `close()` does a final flush after the pipeline
stops. A model snapshot is serialised on the event loop (Drain3 is not thread-safe): ~30 ms for 655 templates + 5,000 training samples, once a minute.
Measured here: writing 61,100 rows (60k IOCs, 50 batches, 1,000 logs) took 240 ms with a worst event-loop stall of 35 ms.

## Failure behaviour
A corrupt file is moved to `state.db.corrupt-<time>` and the service starts empty; an unusable path or a newer schema disables
persistence (error logged, `GET /api/v1/state` shows `enabled: false`) and the service keeps running in memory.

## Limits
One writer per schema/file (see the PostgreSQL section for what sharing does and does not mean). Not encrypted: the file holds redacted log content,
IOCs and token hashes, so protect it like the logs (0600 is set where the OS supports it). Batch proofs are kept for the newest
`LOGUNIFY_INTEGRITY_MAX_BATCHES` batches only, as in memory. Not persisted yet: Drain3 templates, the Isolation Forest (it re-learns
after a restart), threat-intel hit history, metrics counters. The ledger is still a mock; persisting its receipts does not make it real.

API (admin): `GET /api/v1/state` (status, what was restored, last flush), `POST /api/v1/state/flush`.
