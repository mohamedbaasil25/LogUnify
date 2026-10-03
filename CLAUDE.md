# LogUnify: Universal Log Pre-processing Framework

Ingests heterogeneous security logs, normalises them to Elastic Common Schema (ECS), enriches them (templates, ML
anomaly score, MITRE ATT&CK, threat intel), makes them tamper-evident (SHA-256 Merkle batches anchored on a ledger),
reduces noise, and forwards them to SIEMs with CERT-In-compliant retention and incident alerting.

Roles the owner works in: Lead System Architect, Solution Manager, SOC analyst, threat-intel specialist, blockchain developer,
data engineer, DevOps/cloud security architect, SOC manager / compliance officer.

## Architecture

```
sources (Syslog / JSON / CEF / text, HTTP push)
   │
   ▼  Kafka logunify.raw
logunify-flink (PyFlink) ── noise filter → 5-min dedup → zstd frames ──► Kafka logunify.siem (+ .dedup-stats)
   │
logunify-backend (FastAPI)
   parse → ECS → Drain3 template → Isolation Forest score (0-1) → MITRE tag (>0.7) → GeoIP → threat intel (MISP/IOC)
   → Merkle batch (100 records) → mock Fabric anchor → critical alerting (score > 0.9 AND critical technique)
   │
   ▼  Kafka logunify.ecs
logunify-forwarder (Vector) ──► Elasticsearch data stream · Splunk HEC · Wazuh (file + agent); DLQ logunify.ecs.dlq
   lifecycle: hot 0-7d → warm 7-30d → cold 30-180d → delete (Wazuh ISM 181d), snapshot before delete
logunify-dashboard (Next.js) ──► SOC console over the backend API (proxied /api → :8000)
```

## Folder structure

| Path | Contents |
|---|---|
| `logunify-backend/app/` | `parsers/` (syslog, json, cef, text, detect) · `ecs/normalizer.py` · `pipeline/` (bus: memory/Kafka, processor, metrics) · `intel/` (Drain3, anomaly, mitre rules, ecs_mapper) · `enrich/geoip.py` · `threatintel/` (store, misp, service) · `integrity/` (merkle, batcher, ledger, cli) · `alerting/` (rules, calibration, cert_in report, manager, notifiers incl. Slack/Teams, store incl. saved searches) · `search.py` · `api/` · `sources.py` · `mock/generators.py` · `pipeline/` also has `envelope.py` (event.id/hash), `dlq.py`, `stream.py` (SSE) · `archive/` (encrypted raw archive) · `parsers/sdk.py` + `builtin/*.yaml` (parser SDK) · `ecs/taxonomy.py` + `validate.py` · `forwarding/` (async ES Bulk forwarder) · `state/` (aiosqlite persistence) · `listeners/` (syslog UDP/TCP) · `privacy/` (PII redaction) · `security/` (JWT, RBAC guard, hash-chained audit) · `compliance/` (retention proof, PCI/HIPAA/ISO/CERT-In mapping, PDF) · `config.py` (all settings `LOGUNIFY_*`) |
| `logunify-backend/docs/ALERTING.md` | CERT-In 6-hour workflow, field map, calibration, runbook |
| `logunify-backend/docs/PIPELINE.md` | envelope/traceability, no-loss delivery, parser SDK, taxonomy, throughput numbers, scale-out |
| `deploy/`, `compose.yaml`, `.github/workflows/ci.yml` | containers (backend/dashboard/kafka stack built + smoke-tested, CI green on GitHub; flink/vector images not built), hash-pinned locks, offline bundle, `deploy/smoke_test.py` |
| `logunify-backend/docs/CONFIGURATION.md` | where every secret comes from (env vars / secret files), generation and rotation |
| `logunify-backend/docs/FORWARDING.md` | Python ES Bulk forwarder: guarantees, retry table, dead-letter, verification status |
| `logunify-backend/docs/STATE.md` | what is persisted, flush design, failure behaviour, limits |
| `logunify-backend/docs/SECURITY.md` | PII redaction, RBAC, audit log, compliance report: behaviour and limits |
| `logunify-backend/scripts/` | `alert_threshold_survey.py`, `dev_alert_sink.py` |
| `logunify-dashboard/` | `app/`, `components/` (MetricCards, LogStream, SourceConfigurator, SourceList, IntegrityVerifier, Badges, AlertsView, SearchView, CalibrationView), `lib/` (api, types, usePoll, format) |
| `logunify-flink/` | `logunify_flink/` (job, functions, noise, fingerprint, codec, config, pyenv, testing) · `jars/` (Kafka connector, zstd-jni) · `scripts/` (e2e, consume_siem) · `tools/` (Kafka 3.9.1, gitignored) |
| `logunify-forwarder/` | `vector/vector.d/` (00-common, 05-dlq, 10-elasticsearch, 20-splunk-hec, 30-wazuh-file) · `elasticsearch/` (ILM, template, SLM, role, setup.py) · `splunk/` · `wazuh/` · `retention/` (policy_lint, capacity) · `scripts/` (mock_receivers, e2e) · `docs/WORKFLOW.md` · `tools/` (Vector, gitignored) |

## Commands

```bash
# backend (port 8000) + tests
cd logunify-backend && python -m uvicorn app.main:app
python -m app.parsers.cli test --strict                     # parser golden-fixture contract (CI gate)
python scripts/bench_pipeline.py                            # one-core throughput
python -m pytest tests -q                                   # 413 tests (+3 real-Kafka tests: -m kafka, ~2 min, needs Java + a Kafka distribution)
python scripts/mutation_test.py --target app/privacy/pii.py --tests tests/test_pii.py --sample 40   # sampled mutation check (CI gate 80%)
python scripts/bench_pipeline.py --min-eps 300              # throughput regression gate

# dashboard (port 3000); Node is at "C:\Program Files\nodejs"
cd logunify-dashboard && npm run dev        # npm run build · npm run typecheck · npm run e2e (Playwright + axe; build first)

# flink: the Python 3.11 venv MUST be first on PATH (Flink launches workers as `python`; venv path has a space)
cd logunify-flink && export PATH="$(cygpath "$(pwd -W)/.venv/Scripts"):$PATH"
python -m pytest tests -q                                   # 33 tests
python scripts/e2e.py --streaming                           # needs Kafka on 127.0.0.1:9092

# forwarder
cd logunify-forwarder && python -m pytest tests -q          # 54 tests
python retention/policy_lint.py --eps 300 --outage-hours 4  # CI gate for the 180-day rule
python retention/capacity.py --eps 500
```

## Development goals (open, in priority order)

1. **Calibrate the alert threshold**: at 0.9 nothing fires (0 alerts / 58k logs; 0.80 → 6). Use the dashboard `/calibration` view (replay + analyst feedback; `docs/ALERTING.md`) or `alert_threshold_survey.py` on real traffic.
2. **Real IdP**: RBAC + audit exist (HS256 JWT, `LOGUNIFY_AUTH_MODE=jwt`; default `off` = open). Still to do: RS256/JWKS (Keycloak/Entra), mTLS, run the live ILM check against a real cluster.
3. **Remaining deployment work:** build/run the Flink + Vector images, Helm chart. Done: PostgreSQL state backend (schema per replica), signed Drain3/IF persistence, Redis-shared rate limit. Still open: logically shared sources/batches across replicas, Postgres for alerts/audit/revocations, Redis for the lockout limiter. Flink output (`logunify.siem`) has no consumer yet.
3b. **Replace placeholders**: MaxMind GeoIP, live MISP, real Hyperledger Fabric gateway (`submit_anchor`/`get_anchor`), validated ATT&CK analytics.
4. **Validate lifecycle policies on real clusters** (ES ILM, Splunk indexes.conf, Wazuh rules via `wazuh-logtest`, ISM); size with `capacity.py`.
5. **Persistence**: sources, IOC feeds, batches, anchors, recent logs now persist (`state/`, aiosqlite, `docs/STATE.md`). Models (Drain3 templates, IF window) persist when an HMAC key is set. Still in memory: TI hit history, metrics. One writer per file/schema.
6. **API-pull listeners** (stored as config only). Syslog UDP/TCP listeners exist (`listeners/`, no TLS/RFC 5425); HTTP push works.
7. Dashboard: push (SSE/WebSocket) instead of 2 s polling; alerts view.

## Conventions and constraints

- **Be explicit about mock vs real.** Mock: Fabric ledger, GeoIP, demo IOCs (`mock-misp`), MITRE rules (heuristic). Label mocks in code, UI and docs; never present demo data to a regulator.
- **An enrichment/alerting failure must never drop a log** (wrap each stage, count and log the error).
- Secrets never in code, config files or logs: `SecretStr` in the backend, `SECRET[...]` in Vector, webhook URLs logged as `scheme://host` only.
- Verify before claiming: run the tests / an end-to-end check and report what was and wasn't verified.
- **CERT-In** (Directions 28 Apr 2022, form, FAQ): report Annexure I incidents within 6 h of noticing (incident@cert-in.org.in, 1800-11-4949); partial info OK (FAQ Q30); logs kept 180 days (India region by default, FAQ Q35 nuance); NTP to NIC/NPL. LogUnify never files with CERT-In automatically.

## Windows environment notes

- IPv6 loopback is broken: bind Kafka to `127.0.0.1`; librdkafka needs `broker.address.family=v4`.
- Elasticsearch/JDK 17+ fails to open a selector on this Windows build; use mocks or a Linux host.
- Kafka `.bat` scripts hit "input line too long"; start with `java -cp "<libs>\*" kafka.Kafka server.properties`.
- Default `python` is 3.13 (backend); PyFlink uses the 3.11 venv in `logunify-flink/.venv`.
