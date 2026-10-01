# Pipeline guarantees: traceability, no-loss delivery, parsers, taxonomy, scale-out

## 1. Traceability: from a normalized record back to the exact bytes received
Every log gets an **envelope at the door** (`app/pipeline/envelope.py`), before it enters the queue/Kafka:

| field | meaning |
|---|---|
| `event.id` | UUIDv7 minted when the log is accepted. A raw-topic record from a producer that did not set one gets a deterministic UUIDv5 of `topic/partition/offset`, so re-reading it never creates a second identity |
| `event.hash` | SHA-256 of the raw bytes exactly as received (ECS `event.hash`) |
| `event.created` / `event.ingested` / `@timestamp` | received / processed / when it happened (missing event time falls back to receive time and is flagged `logunify.timestamp.source`) |
| `logunify.source.id`, `logunify.transport`, `logunify.origin.kafka.*`, `logunify.origin.peer` | where it came from (source, `http`/`syslog`/`replay`, Kafka coordinates, HTTP peer) |
| `logunify.parser.name` / `.version` | the exact parser that produced the record |
| `logunify.raw.redacted` | `event.original` differs from the received bytes because PII was masked |

The Merkle tree seals the normalized document, which contains `event.id` and `event.hash`, so a ledger anchor covers the link to the raw log.
`event.id` is also the Elasticsearch `_id` (Vector and the Python forwarder agree), so replays and retries are idempotent.

**Raw archive** (`app/archive`, `LOGUNIFY_RAW_ARCHIVE_ENABLED`): the unredacted bytes, compressed and AES-256-GCM encrypted (event.id bound as authenticated
data), in append-only segments with a hash index; whole-segment retention. It refuses to start without a key when PII redaction is on.
**`GET /api/v1/trace/{event.id}`** (analyst) returns the document, its Merkle batch + anchor, and `checks` (raw hash == `event.hash`, archive intact, document ==
archived hash) with a verdict. `?include_raw=true` returns the unredacted text to admins only and is written to the audit log.
Limits: the archive queue is bounded (overflow is counted in `dropped`, not blocked); a crash can lose records still queued; key rotation is not implemented.

## 2. No-loss delivery
* **Door:** only oversize / queue-full logs are refused, and the sender is told (`dropped_at_door`). Everything accepted ends up normalized or dead-lettered.
* **Dead-letter store** (`app/pipeline/dlq.py`, `GET /api/v1/dlq`, `POST /api/v1/dlq/replay`): parse errors, internal errors, strict-schema violations and unpublishable logs
  are kept with raw bytes + envelope (JSONL, fsynced, replayable with the original `event.id`). It is capped; beyond the cap records are counted `lost_full`.
* **Books:** `metrics.reconciliation` = `accepted - normalized - dead_lettered - in_flight` must be 0 when quiescent (`GET /api/v1/metrics`, `/metrics/dead-lettered`).
* **Kafka:** producers use `acks=all` + idempotence; the consumer does not auto-commit. A fetched batch is processed in slices (event loop stays free), ECS documents are
  sent without waiting and acknowledged **once per batch**, and offsets commit only after every acknowledgement. Broker trouble is retried (offsets stay uncommitted)
  for `LOGUNIFY_KAFKA_PUBLISH_MAX_WAIT_S`, then the raw log is dead-lettered. Result: at-least-once; a crash re-reads the batch and ids are identical.
  Verified against a real broker (`pytest -m kafka`): round trip with lag 0, crash before commit (240 messages, 120 unique ids), broker killed and restarted mid-publish (nothing lost).
* **Not covered:** a hard crash loses what is only in an in-memory queue in front of the Elasticsearch forwarder / raw archive (see their docs); the in-memory bus (dev) loses its queue.

## 3. Parsers: onboarding a source without touching the pipeline (`app/parsers/sdk.py`)
1. **Declarative YAML** in `LOGUNIFY_PARSER_DIR`: regex with named groups (`kind: regex`) or JSON paths (`kind: json`), field mapping with types/transforms/drop rules, conditional rules,
   timestamp format, sniff rule. Shipped examples: `app/parsers/builtin/{nginx_access,iptables_log,aws_cloudtrail}.yaml`.
2. **Python plugin** (`*.py` with `PARSERS = [...]`) or 3. **entry point** in group `logunify.parsers`.
Detection: every parser `sniff()`s, the most confident wins (ties: priority, then registration order); a source/ingest `format` selects a parser by name. A broken parser file is skipped
and reported in `GET /api/v1/parsers` (`errors`), never fatal. Regexes are linted for catastrophic backtracking and run on the first 8 KB only. **Parser files are code-equivalent:**
deploy them read-only; the API never accepts uploads.
Developer loop: `python -m app.parsers.cli scaffold NAME` -> edit -> `try NAME "line"` -> `test NAME --update` (review the golden file) -> `test --strict` in CI.
`parser_fixtures/<parser>/*.log` + `.expected.json` are the contract: each case must parse, be auto-detected as that parser, and produce zero ECS violations.

## 4. Taxonomy
`app/ecs/taxonomy.py` completes `event.category/type/outcome/module` from small rule tables, the same way for every source (never overriding a parser). `app/ecs/validate.py` checks every
document (`LOGUNIFY_TAXONOMY_MODE`: `off` | `warn` default, counted in `metrics.schema_violations` | `strict` = dead-letter violators). The validator knows ~230 common ECS fields
(types, enums, required fields, known roots); unknown fields under a valid ECS root pass untyped. `load_ecs_flat()` loads the full official schema if you supply `ecs_flat.yml`.
Rules are heuristic ("sshd logs are authentication events"), not proof.

## 5. Throughput and scale-out
Measured on this development laptop (Windows, Python 3.13, mock logs, one core per worker, Kafka broker on the same machine; your hardware will differ):

| what | events/s |
|---|---|
| normalization only, one core, full pipeline (`scripts/bench_pipeline.py`) | ~3,900 (was ~920 per-log; batching + cheaper PII gating) |
| same, ML scoring off | ~9,000 |
| end-to-end via Kafka, `acks=all`, 1 worker (`scripts/load_test_kafka.py`) | ~1,300-1,650 |
| end-to-end via Kafka, 2 workers / 4 workers | ~2,500 / ~3,100 (all processes plus the broker share one laptop) |

1 billion events/day is ~11,600 events/s on average (3-5x at peak). At the single-worker figures that is **7-9 workers on average and roughly 25-40 at peak**, and 10 billion/day is ten times that:
horizontally scalable by design (Kafka consumer group, partitions >= workers, `LOGUNIFY_WORKER_ID` + `{worker}` path templating so replicas never share a SQLite file), but **not demonstrated at that
volume here**, and not on a multi-node broker cluster. Costs you should know: ML scoring (Drain3 + Isolation Forest) is ~55% of per-log CPU; the audit log commits to SQLite per request;
Merkle batches, alert state and the durable state are **per worker** (a multi-replica deployment has per-worker stores; an external database would be needed for one shared view).
The Flink job (noise filter / 5-minute dedup / zstd frames) writes `logunify.siem`; nothing in this repository consumes that topic, and Vector reads `logunify.ecs`. Treat Flink as an optional,
separate output stream for external consumers until that is wired deliberately.
