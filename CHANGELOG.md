# Changelog

## Unreleased
- **State:** optional PostgreSQL backend (`LOGUNIFY_STATE_DATABASE_URL`, schema per replica, advisory-lock ownership, reconnect); SQLite default unchanged (schema v2, v1 files upgrade in place).
- **Models survive restarts:** Drain3 templates and the Isolation Forest training window are persisted, HMAC-signed and verified before loading.
- **Redis:** `LOGUNIFY_REDIS_URL` shares the request-rate limit across replicas (fails open to per-replica).
- **Parser library:** Windows Security, Linux auditd, Okta, Entra ID sign-in, FortiGate, Palo Alto TRAFFIC (declarative, golden fixtures; see PIPELINE.md for limits).
- CI runs the backend suite against real PostgreSQL 16 and Redis 7 service containers.

## 1.0.0
First release candidate.

- **Pipeline:** parse → PII redaction → ECS → Drain3 + Isolation Forest (batched) → MITRE → GeoIP (mock) → threat intel → Merkle batches (mock ledger anchor) → CERT-In alerting.
- **Traceability:** `event.id` (UUIDv7) + `event.hash` on every record, encrypted raw archive, `/api/v1/trace/{event.id}`.
- **No-loss path:** dead-letter store + replay, reconciliation counters, Kafka `acks=all` + commit-after-ack, consumer supervisor, `/ready`.
- **Parsers:** SDK (declarative YAML, plugins, entry points), golden-fixture contract, ECS validation, unified taxonomy.
- **Security/compliance:** JWT RBAC, hash-chained audit log, PCI/HIPAA/ISO/CERT-In control mapping + retention proof (PDF).
- **Operations:** syslog UDP/TCP listeners, durable state (aiosqlite), Elasticsearch Bulk forwarder, live log push (SSE), containers + offline bundle, CI.
- **Release hardening:** consumer supervisor + `/ready`, stable replica identities (`LOGUNIFY_WORKER_ID=auto` leases `w0..wN` slots), demo traffic generator OFF by default, container defaults to JWT auth.
- Known limits: see README ("What is real and what is not") and `logunify-backend/docs/PIPELINE.md`.
