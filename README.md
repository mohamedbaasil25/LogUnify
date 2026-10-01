# LogUnify

Universal log pre-processing framework: ingest heterogeneous security logs, normalise them to Elastic Common Schema (ECS), enrich
them, make them tamper-evident, reduce noise, and forward them to SIEMs with CERT-In-oriented retention and incident alerting.

```
sources (Syslog UDP/TCP · JSON · CEF · text · HTTP push)
   │
   ▼  Kafka logunify.raw
logunify-flink (PyFlink)   noise filter → 5-min dedup → zstd frames → Kafka logunify.siem
   │
logunify-backend (FastAPI)
   parse → PII redaction → ECS → Drain3 template → Isolation Forest score → MITRE tag → GeoIP → threat intel
   → Merkle batch (100 records) → ledger anchor → critical alerting (CERT-In 6-hour workflow)
   │
   ▼  Kafka logunify.ecs  (or direct Elasticsearch Bulk forwarding)
logunify-forwarder (Vector)   Elasticsearch · Splunk HEC · Wazuh, hot/warm/cold lifecycle, 180-day retention policies
logunify-dashboard (Next.js)  SOC console over the backend API
```

| Folder | What it is | Docs |
|---|---|---|
| [`logunify-backend/`](logunify-backend) | FastAPI service: parsers, ECS, intelligence, integrity, alerting, RBAC + audit, PII redaction, compliance reports, syslog listeners, durable state, Elasticsearch forwarder | [README](logunify-backend/README.md), [docs/](logunify-backend/docs) |
| [`logunify-flink/`](logunify-flink) | PyFlink noise-reduction / dedup / compression job | [README](logunify-flink/README.md) |
| [`logunify-forwarder/`](logunify-forwarder) | Vector pipeline, ES/Splunk/Wazuh configs, retention policy linter and capacity planner | [README](logunify-forwarder/README.md) |
| [`logunify-dashboard/`](logunify-dashboard) | Next.js SOC dashboard | [README](logunify-dashboard/README.md) |

## Quick start (development)

```bash
# backend on :8000 (in-memory bus; add LOGUNIFY_MOCK_ENABLED=true for demo traffic)
cd logunify-backend
python -m pip install -r requirements.txt
cp .env.example .env            # optional; every setting is a LOGUNIFY_* variable
python -m uvicorn app.main:app

# dashboard on :3000 (proxies /api to the backend)
cd logunify-dashboard && npm install && npm run dev
```

Tests: `python -m pytest tests -q -m "not kafka"` in `logunify-backend` (354, plus 2 Linux-only worker-slot tests that run in CI and in the container; 3 more against a real Kafka broker with `-m kafka`), `logunify-forwarder` (54) and `logunify-flink` (33, needs its
Python 3.11 venv). Dashboard: `npm run typecheck && npm run build`. See [`CLAUDE.md`](CLAUDE.md) for the exact commands.

## What is real and what is not

Be explicit about this before showing the system to anyone, especially an auditor or regulator.

* **Mock / placeholder:** the Hyperledger Fabric ledger (anchors are simulated), GeoIP, the demo IOC feed (`mock-misp`), and the MITRE
  ATT&CK rules (heuristic, not validated detection content). Mock data is labelled in code, UI and reports.
* **Not verified against real systems:** Elasticsearch, Splunk and Wazuh (tested against protocol stubs; Elasticsearch cannot run on the
  development machine), the live MISP client, Elasticsearch ILM checks on a real cluster, the Python Bulk forwarder.
* **Not run:** the Flink and Vector images / `siem` profile (the backend + dashboard images and the Kafka compose stack were built and smoke-tested, and the GitHub Actions workflow passes all 8 jobs, including the real-Kafka tests and the Trivy image scan; see `deploy/README.md`).
* **Not implemented:** Helm/Kubernetes manifests, TLS for syslog, mTLS between components, OIDC/JWKS (RS256) token verification (HS256 shared-secret JWT only),
  multi-instance state sharing.
* **Defaults are open for development:** `LOGUNIFY_AUTH_MODE=off` treats every caller as admin. Set `jwt` before exposing the API.
* **Alert threshold:** at the specified 0.9 anomaly score nothing fired on the test corpus; calibrate on real traffic with
  `logunify-backend/scripts/alert_threshold_survey.py`.
* LogUnify **never files with CERT-In automatically**; it drafts the incident report and tracks the 6-hour clock.

## Configuration and secrets

Secrets are read from environment variables (`LOGUNIFY_*`) or secret files, never from code. `.env` is git-ignored; `.env.example`
files hold placeholders only. See [`logunify-backend/docs/CONFIGURATION.md`](logunify-backend/docs/CONFIGURATION.md).
Large local tools (`logunify-*/tools/`, Flink jars, virtualenvs, `node_modules`) are git-ignored; the Flink README says where to download the jars.

## Documentation

[Alerting and the CERT-In workflow](logunify-backend/docs/ALERTING.md) · [Security: PII, RBAC, audit, compliance](logunify-backend/docs/SECURITY.md) ·
[Durable state](logunify-backend/docs/STATE.md) · [Elasticsearch forwarding](logunify-backend/docs/FORWARDING.md) ·
[Pipeline guarantees, parsers, scale-out](logunify-backend/docs/PIPELINE.md) · [Containers and air-gap](deploy/README.md) ·
[Configuration](logunify-backend/docs/CONFIGURATION.md) · [Forwarder workflow and retention](logunify-forwarder/docs/WORKFLOW.md)
