# Elasticsearch forwarding (`app/forwarding/elasticsearch.py`)

`bulk_send(session, url, items)` is the single-request function (aiohttp, one Bulk call, every item classified);
`ElasticsearchForwarder` wraps it with a queue, batching, retries and a dead-letter file. Enable with `LOGUNIFY_ES_FORWARD_ENABLED`
(+ `LOGUNIFY_ES_URL`, `LOGUNIFY_ES_FORWARD_API_KEY`). The pipeline hands each redacted ECS document to `forwarder.submit()` (sync, O(1)).

**Guarantee: at-least-once, idempotent.** Each document is a `create` action with `_id = sha256(document JSON)[:40]`. A retry after a
lost response gets 409 for what Elasticsearch already has, which counts as delivered: no duplicates, no loss. (`create` is also what
data streams require.) Vector's sink uses a different `_id`, so never run both on one index.

| situation | behaviour |
|---|---|
| connection refused / reset / dropped mid-request, timeout, truncated or non-JSON reply, HTTP 408/429/500/502/503/504 | whole batch retried, exponential backoff + full jitter (`Retry-After` honoured), up to `MAX_RETRIES` per document |
| partial failure (200 with `errors:true`) | only items answered 429/5xx are resent; 409 = done |
| item rejected 4xx (e.g. mapping error) | never retried; dead-letter file, `retryable:false` |
| 413 | batch split in half and resent |
| 401 / 403 | documents held, slow retry that does **not** spend the retry budget; `healthy=false` |
| retries exhausted, queue full, shutdown | dead-letter JSONL (`fsync`ed), `retryable:true`; `POST /api/v1/forwarding/elasticsearch/replay` re-queues them |

Counters (`GET /api/v1/forwarding/elasticsearch`, admin): alert on `healthy=false`, `dead_lettered` growing, and any `lost_*` > 0.
**Documents can still be lost in two counted cases:** the in-memory spill buffer is full while the queue is full (`lost_spill_full`), or
the dead-letter file reached `DLQ_MAX_MB` (`lost_dlq_full`). Both need a long outage beyond the configured buffers. A crash (kill -9)
loses whatever is only in the in-memory queue (up to `QUEUE_MAX`); only shutdown paths flush the queue to disk.

The event loop is not blocked: JSON encoding and gzip run in a worker thread per batch (measured: 20,000 x 1.5 KB documents, worst loop
stall < 300 ms asserted in tests). Security: https required unless loopback, TLS verified (optional CA file), API key only in the
Authorization header, URL logged as scheme://host:port.

**Verification status:** 17 tests against an in-process stub of the Bulk API (drops before/after indexing, 503, HTML 502, partial 429,
mapping errors, 413, 401, timeouts, overflow, shutdown, recovery). **Not verified against a real Elasticsearch**, nor over TLS or
with a real API key: it cannot run in the development environment. Run it against a real cluster before relying on it.
