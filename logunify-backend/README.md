# LogUnify backend

FastAPI service that ingests raw logs (Syslog RFC3164/5424, JSON, CEF) from Kafka, normalizes them to
Elastic Common Schema 8.11, and exposes pipeline metrics over REST.

```
raw logs ──► Kafka  logunify.raw ──► Pipeline: detect → parse → ECS ──► ring buffer + metrics
 (REST /ingest, mock generator)                                    └──► Kafka logunify.ecs (Kafka mode)
```

## Run
```bash
pip install -r requirements.txt
python -m uvicorn app.main:app --reload        # in-memory bus + built-in mock generator, no Kafka needed
python -m pytest
```
Docs: http://localhost:8000/docs

### With Kafka
```bash
docker compose up -d kafka
set LOGUNIFY_KAFKA_ENABLED=true        # PowerShell: $env:LOGUNIFY_KAFKA_ENABLED="true"
python -m uvicorn app.main:app
python -m app.mock.generators --rate 200 --seconds 30   # separate producer process
```
All settings are env vars prefixed `LOGUNIFY_` (see `.env.example`).

## API
| Endpoint | Purpose |
|---|---|
| `GET /health` | status, bus type |
| `GET /api/v1/metrics` | received / processed / dropped, drop rate, throughput (1s/10s/60s), compression ratio, per-format counts |
| `GET /api/v1/metrics/throughput?window=60` | per-second series for charts |
| `GET /api/v1/metrics/dropped` | drops by reason (`parse_error:*`, `oversize`, `queue_overflow`, ...) |
| `GET /api/v1/metrics/compression` | bytes in/out, ratio, % saved |
| `POST /api/v1/ingest` | `{"logs": [...], "format": "syslog"\|"json"\|"cef"?}` → published to the raw topic |
| `POST /api/v1/parse` | synchronous dry-run of one log → ECS |
| `GET /api/v1/logs/recent?limit=&format=` | newest-first ECS events |
| `GET /api/v1/anomalies?limit=` | logs scoring > threshold, with `threat.technique.*` |
| `GET /api/v1/templates?limit=` | most frequent Drain3 templates |
| `GET /api/v1/integrity/batches` | sealed Merkle batches (id, root, count, time range, anchor receipt) |
| `GET /api/v1/integrity/batches/{id}/proof/{index}` | record + leaf hash + Merkle proof path |
| `POST /api/v1/integrity/seal` | seal the current partial batch now |
| `POST /api/v1/integrity/anchor` | **mock** Fabric commit of a batch root → `{tx_id, timestamp, block_number, ...}` |
| `GET /api/v1/integrity/anchors/{tx_id}` | look up an anchor receipt |
| `POST /api/v1/integrity/verify` | `{record \| leaf_hash, proof, merkle_root, batch_id?}` → `{valid, proof_valid, anchor_root_matches, ...}` |
| `POST /api/v1/integrity/hash` | SHA-256 leaf hash + canonical JSON of a record |
| `POST /api/v1/integrity/verify-batch` | `{batch_id, records[], expected_root?}` → rebuilds the root, lists `tampered_indexes` / missing / extra |
| `GET /api/v1/integrity/batches/{id}/audit` | server self-audit: rehash stored records vs sealed root vs ledger anchor |
| `GET /api/v1/threatintel/status` | feeds, indicator counts, last sync / error (never the API key) |
| `POST /api/v1/threatintel/sync` | pull MISP now |
| `GET /api/v1/threatintel/matches` | recent logs that hit an indicator |
| `GET /api/v1/threatintel/lookup?value=` | is this IP / domain / hash a known indicator? |
| `POST /api/v1/threatintel/iocs` | import analyst indicators (feed `manual`) |
| `GET /api/v1/alerts?status=` · `/{id}` · `/{id}/cert-in-report[?format=text]` · `/{id}/evidence` · `/{id}/events` | critical alerts + CERT-In 6-hour report drafts (**`X-API-Key` required**, see below) |
| `POST /api/v1/alerts/{id}/ack` · `PATCH …/details` · `POST …/report` · `POST …/close` · `POST /api/v1/alerts/test` | analyst workflow, audit-trailed; channel test |

**Compression ratio** = raw bytes of processed logs ÷ ECS bytes after streaming zlib (shared dictionary, like Kafka batch compression). The ECS
docs include `event.original`, so the ratio measures the full normalized record, not just the parsed fields.

## Layout
`app/parsers` (one module per format + `detect.py`) · `app/ecs/normalizer.py` · `app/pipeline` (`bus.py`
memory/Kafka, `processor.py`, `metrics.py`) · `app/api` · `app/mock/generators.py` · `tests/`

## Intelligence layer (`app/intel`)
Every ingested log (any format, including unstructured text) message goes through:
1. **Drain3** (`template_miner.py`): online template mining; IPs and numbers are masked, `key=value` is split. Each
   log gets `logunify.template.id` / `.text`.
2. **ECS mapping** (`ecs_mapper.py`): extracted parameters are named by the word before each slot
   (`from <IP>` → `source.ip`, `to <IP>` → `destination.ip`, `port <NUM>` → the port of the preceding IP,
   `user <*>` → `user.name`, `status <NUM>` → `http.response.status_code`, ...). Fields set by a format parser are never overridden.
3. **Isolation Forest** (`anomaly.py`): features = new-template flag, template frequency share, severity, message
   length, parameter count, auth-failure flag, external source IP. Score is calibrated to 0.0-1.0 so that ~1% of
   training-like traffic exceeds 0.7. `logunify.anomaly.score` and `.model_ready` are on every event.
4. **MITRE tag** (`mitre.py`): score > 0.7 adds `threat.technique.id` (default **T1078**, T1110 for auth failures).
   **These are placeholders**, flagged with `labels.mitre_placeholder`, not real detections.

Warm-up: the first 50 logs are not learned from and the model fits after 200 learned samples (score is 0.0 and
`model_ready=false` until then), then refits in a background thread every 1000 samples on a 5000-sample window.
Settings: `LOGUNIFY_INTEL_ENABLED`, `ANOMALY_THRESHOLD`, `ML_WARMUP`, `ML_REFIT_EVERY`, `ML_WINDOW`.

## Integrity layer (`app/integrity`)
Every 100 processed ECS records (`LOGUNIFY_INTEGRITY_BATCH_SIZE`) are sealed into a SHA-256 Merkle tree and, with
`LOGUNIFY_INTEGRITY_AUTO_ANCHOR=true` (default), the root is committed to a **mock** Hyperledger Fabric ledger.
- Records are hashed as canonical JSON (sorted keys, compact). Leaf = `SHA256(0x00‖record)`, node =
  `SHA256(0x01‖left‖right)` (domain separation against second-preimage attacks); an unpaired node is promoted, not duplicated.
- `/verify` recomputes the leaf from the submitted record and folds the proof, so any edited field fails. With
  `batch_id` it also compares the root to the ledger-anchored one, so a self-consistent forged root + proof still fails.
- Standalone script: `python -m app.integrity.cli logs.ndjson [--batch-size 100] [--proof N]` or `--mock 250`.

Limits: the ledger is an in-memory mock (no endorsement/ordering, anchors vanish on restart; a real integration
implements the same `submit_anchor` / `get_anchor` methods on a Fabric Gateway client). Batches and their records
are kept in memory (last 50). A proof shows a record was in the batch that produced the root; trust comes from
that root being anchored on a real ledger. `POST /parse` dry-runs also enter batches.

### Verifying batches
Three levels: `/verify` (one record **or** just its SHA-256 leaf hash + proof → root), `/verify-batch` (submit all
records; the root is rebuilt and compared with the stored batch root, the ledger-anchored root and an optional
root you got elsewhere, and altered records are pinpointed by index), and `/batches/{id}/audit` (the server rehashes what
it holds, catching tampering with its own copy). The ledger anchor is the trust root; the stored root alone is not.

## Threat intelligence (`app/threatintel`)
Every ingested log is cross-referenced against an in-memory IOC index (IPs incl. CIDR, domains with parent-domain
matching, MD5/SHA-1/SHA-256). Observables come from ECS fields (`source.ip`, `destination.ip`, `url.domain`,
`dns.question.name`, `file.hash.*`, ...) **and** from a bounded regex scan of the message text, so unstructured logs
match too. A hit adds `threat.indicator.*` (type, ip/domain/hash, provider, confidence, description, MISP event
link), `logunify.ti.*`, and sets `event.kind: alert`.

- **MISP**: set `LOGUNIFY_MISP_URL` and `LOGUNIFY_MISP_KEY`. The client calls `POST /attributes/restSearch`
  (`to_ids=1`, last `LOGUNIFY_MISP_LOOKBACK`, paged) every `LOGUNIFY_MISP_SYNC_MINUTES`, expands composite types
  (`domain|ip`, `filename|sha256`, `ip-dst|port`), and indexes hosts of malicious URLs. If a sync fails, the previous
  indicators stay active and the error is shown in `/threatintel/status`. Catch-all CIDRs (prefix < /8) and loopback
  values are rejected so one bad row can't flag everything.
- **Without MISP**, 9 fictional demo indicators (`mock-misp`) are loaded so the pipeline and UI can be exercised
  (`LOGUNIFY_TI_MOCK_FEED=false` to disable).
- The MISP client is tested against a mocked transport only; it has **not** been run against a live MISP instance.

## Critical alerting and CERT-In 6-hour reporting (`app/alerting`)
When a log's anomaly score **exceeds 0.9** and it matches a **critical, rule-matched MITRE ATT&CK technique**, LogUnify raises a
high-priority alert by **HMAC-signed webhook and/or email**. Each alert carries a **form-aligned CERT-In incident report draft** (Annexure I
incident type, affected system, occurrence/detection times in IST, evidence with SHA-256 and Merkle reference, what is still missing), the **6-hour
due time**, deadline reminders, and an audit-trailed workflow (acknowledge → complete → report → close). Alerts are durable (SQLite) and survive restarts.
**Nothing is ever filed with CERT-In automatically**: a human verifies and submits, then records it.

**Read [docs/ALERTING.md](docs/ALERTING.md)** before enabling it. Key points: the official CERT-In form is "general guidance, not mandatory", so this
module fills every field it can and lists the gaps instead of claiming "mandatory" fields; the requested 0.9 threshold is almost unreachable with the current
scoring (measured: 0 alerts per 58,000 generated logs; 6 at 0.80), so calibrate with `python scripts/alert_threshold_survey.py`; MITRE tags are heuristic.
Try it locally with `python scripts/dev_alert_sink.py` (signature-verifying webhook + SMTP sink). Enable the API with `LOGUNIFY_ALERT_API_KEY`.

Not yet included: real ATT&CK analytics, real GeoIP data, real Fabric integration, STIX/TAXII and other feed types.

## Security & compliance core
PII redaction, JWT RBAC (viewer/analyst/admin), a hash-chained audit log and PCI/HIPAA/ISO/CERT-In compliance reports with a retention proof (PDF). See [docs/SECURITY.md](docs/SECURITY.md).

## Syslog listeners (`app/listeners`)
UDP and TCP, RFC 3164 / 5424 (parsed by `parsers/syslog.py` inside the pipeline), TCP framing by octet counting or newline (RFC 6587).
Enable with `LOGUNIFY_SYSLOG_UDP_PORT` / `LOGUNIFY_SYSLOG_TCP_PORT`, or by creating a `syslog` source (admin) which binds its port.
A bounded queue decouples sockets from the pipeline: UDP drops (counted) when full, TCP back-pressures. Counters: `GET /api/v1/sources/listeners`.
No TLS (RFC 5425) and no source authentication; bind is loopback by default. Port 514 needs elevated rights on Linux.

## Durable state (`app/state`)
Sources, IOC feeds, Merkle batches + anchors and recent logs survive restarts (aiosqlite, background flush, no work on the event loop). See [docs/STATE.md](docs/STATE.md).

## Elasticsearch forwarding (`app/forwarding`)
Async Bulk API forwarder (aiohttp) with retries, idempotent ids and a dead-letter file. See [docs/FORWARDING.md](docs/FORWARDING.md).
