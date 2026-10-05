# Changelog

## Unreleased
- **Controlled demo activity:** `New-LogUnifyDemoActivity.ps1` causes a capped burst of real Windows events (failed logons for a non-existent user, harmless processes, optional benign encoded PowerShell) with a manifest; refuses on domain controllers and rapid re-runs; documented as test activity, not a baseline.
- **Synthetic (test) sources:** a source tagged `synthetic` is labelled, never trains Drain3 / the Isolation Forest, is excluded from calibration replay and feedback (opt-in checkbox / `include_synthetic`), and its alerts are flagged TEST. `send_windows_samples.py --http-url` for drills; `docs/WINDOWS_SECURITY.md` section 8b (one-day calibration).
- **TLS from day one for Windows forwarders:** `make-certs.sh` (private CA, server + per-host client certificates), tested mutual-TLS stunnel configuration, `send_windows_samples.py --tls-*`, and `WINSERVER-01.md` with ready-to-run commands.
- **Windows Security deployment pack** (`deploy/windows-security/`): audit-policy and NXLog installer scripts (dry-run by default), stunnel mutual-TLS example, env template, and `scripts/verify_windows_onboarding.py` (service / source / loss / parsed fields / time zone vs backlog / event mix / buffer horizon). Parser now sets `user.name` from the subject for 4672 / 4688 / 4697 / 7045 / 1102 / 104.
- **Windows Security onboarding:** runbook (`docs/WINDOWS_SECURITY.md`), compose overlay, synthetic sender; parser accepts NXLog `Hostname`; event-ID MITRE rules (log cleared, privileged group add, audit policy change); parser SDK `copy` / `first_of`; **recent-events log now saved incrementally** (a 10k buffer flush went 570 ms to 15 ms) and search no longer flattens every event.
- **Alert calibration:** dashboard `/calibration` + `GET /api/v1/alerts-calibration` (replay funnel, threshold sweep, candidate preview, confidence, analyst feedback incl. CERT-In on-time rate) and admin-only, time-limited, audited suppression rules.
- **Analyst workflow:** alert assignment (+ owner filter, notice to channels / assignee mailbox), append-only case notes, Slack and Teams channels, log search with a time range over the events held, saved searches (private / shared); dashboard: Owner column, Mine / Unassigned, notes panel, new Search page. E2E + axe cover them.
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
