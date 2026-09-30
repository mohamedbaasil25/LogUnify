# Durable state (`app/state/store.py`, aiosqlite)

Saved to `LOGUNIFY_STATE_DB_PATH` (default `data/state.db`) and reloaded at startup, before the pipeline, threat-intel sync or any
listener starts:

| state | notes |
|---|---|
| event sources | the plaintext HTTP token is **never** written: only its SHA-256 (ingest compares hashes), so a restored source keeps working with the token it was issued. Syslog sources re-bind their ports |
| IOC feeds `manual`, `misp` | demo feeds (`mock*`) are not saved; a saved `misp` feed is restored only if MISP is still configured (otherwise nothing could refresh it) |
| Merkle batches, open batch, batch sequence, ledger anchors | ids never repeat after a restart; proofs and anchors survive; restored batches are re-hashed and a mismatch with the sealed root is logged and shown by `/integrity/batches/{id}/audit` |
| recent logs, anomalies | optional (`LOGUNIFY_STATE_PERSIST_LOGS`); already PII-redacted |

## How it stays out of the real-time path
Snapshots are shallow copies on the event loop (microseconds); JSON serialisation runs in a worker thread, item by item; SQL runs on
aiosqlite's thread. Only what changed since the last flush is written (unchanged state: 0 rows, ~2 ms). One transaction per flush (WAL);
change markers advance only after the commit, so a failed flush is retried in full. `close()` does a final flush after the pipeline
stops. Measured here: writing 61,100 rows (60k IOCs, 50 batches, 1,000 logs) took 240 ms with a worst event-loop stall of 35 ms.

## Failure behaviour
A corrupt file is moved to `state.db.corrupt-<time>` and the service starts empty; an unusable path or a newer schema disables
persistence (error logged, `GET /api/v1/state` shows `enabled: false`) and the service keeps running in memory.

## Limits
Single process only (no sharing between instances: that needs a real database). Not encrypted: the file holds redacted log content,
IOCs and token hashes, so protect it like the logs (0600 is set where the OS supports it). Batch proofs are kept for the newest
`LOGUNIFY_INTEGRITY_MAX_BATCHES` batches only, as in memory. Not persisted yet: Drain3 templates, the Isolation Forest (it re-learns
after a restart), threat-intel hit history, metrics counters. The ledger is still a mock; persisting its receipts does not make it real.

API (admin): `GET /api/v1/state` (status, what was restored, last flush), `POST /api/v1/state/flush`.
