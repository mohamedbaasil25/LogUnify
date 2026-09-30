# Security & compliance core

Four controls added on top of the pipeline. What each does, and what it does **not** do.

## 1. PII redaction (`app/privacy/pii.py`)
Runs in `Pipeline.process` right after parsing, before Drain3, scoring, threat intel, alerting, Merkle batching and the ECS topic,
so masked values never reach the SIEM, alert evidence or a batch. Covers `event.original`, `message` and every string field.

| type | rule |
|---|---|
| card | 13-19 digits, plausible network prefix, **Luhn** |
| email | needs an alphabetic TLD (`user@10.0.0.5` untouched) |
| ssn | US SSN, invalid area/group/serial ranges excluded |
| aadhaar | 12 digits starting 2-9, **Verhoeff** checksum |
| pan | Indian PAN, valid holder-type letter |
| phone | Indian mobile; off by default (10-digit numbers are ambiguous in logs) |

`mask` -> `[PII:card]`; `hash` -> `[PII:card:<10 hex>]`, a keyed HMAC pseudonym: the same value correlates across logs, and cannot be
brute-forced without the key. A failure **fails closed and keeps the log** (free text replaced by `[PII:redaction_failed]`, counted).
Counts by type are in `/api/v1/metrics` -> `pii`.
Limits: heuristic (names, addresses, MRNs, DOBs, free-text PHI are not detected); the raw Kafka topic `logunify.raw` still holds the
originals until it expires, so restrict and expire it.

## 2. RBAC (`app/security/rbac.py`, `tokens.py`)
`LOGUNIFY_AUTH_MODE=jwt` requires `Authorization: Bearer <JWT>`. Roles come from a claim (`roles`, or `realm_access.roles`); the highest
known role wins. `off` (default) keeps the old open behaviour, logs a warning, and every caller is `anonymous` admin.

| role | can |
|---|---|
| viewer | metrics, integrity summaries/verify/hash, TI status |
| analyst | + raw logs, anomalies, templates, proofs, batch verify/audit, alerts and CERT-In drafts, TI matches/lookup, source list, ingest |
| admin | + sources create/delete, seal/anchor, IOC import/sync, audit log, compliance reports |

`/health` is public. `/api/v1/sources/{id}/ingest` keeps its per-source `X-Source-Token`. The alert API still accepts `X-API-Key`
(treated as `analyst`). jwt mode refuses to start without a >= 32-byte secret.
**Not implemented:** RS256/ES256 + JWKS discovery, i.e. what Keycloak / Entra ID issue by default. Tokens must be HS256 signed with the
shared secret (a gateway can mint them). Swapping `tokens.decode` for PyJWT+JWKS is the only change needed; roles and audit are IdP-agnostic.
Dashboard: **Access token** button stores the JWT in `sessionStorage`.

## 3. Tamper-evident audit log (`app/security/audit.py`, `/api/v1/audit`)
Every guarded call (including 401/403 denials) appends `{actor, role, auth, action, resource, outcome, client, detail}` to SQLite with
`hash = H(prev_hash || record)`; `H` is HMAC-SHA256 when `LOGUNIFY_AUDIT_HMAC_KEY` is set. Triggers reject UPDATE/DELETE.
`POST /audit/verify` recomputes the chain; `POST /audit/anchor` commits the head to the ledger (**mock** today); `GET /audit/head` gives a
value to witness elsewhere. Polled reads (metrics, recent logs) are sampled to one record per actor per window with a `coalesced` count;
proof downloads, evidence, CERT-In drafts and every change are always recorded.
Limits: it records the authorised *attempt*, not the outcome; tail truncation is only detectable against a witnessed head; an unkeyed
chain can be rebuilt by someone with DB write access.

## 4. Compliance report (`app/compliance`, `/api/v1/compliance/*`, `python -m app.compliance.cli`)
* **Retention proof, static:** parses ILM, SLM, Splunk `indexes.conf`, Wazuh ISM + snapshot policy and runs `policy_lint`. Proves intent.
* **Retention proof, live:** with `LOGUNIFY_ES_URL`, read-only `_ilm/policy` and `_ilm/explain`: policy present, delete age >= 180 d,
  every `.ds-logs-logunify-*` index managed by it, none in ILM error. Tested against a stubbed API only; **never run against a real
  cluster** (Elasticsearch does not start on the dev machine). Splunk/Wazuh: static only.
* **Control mapping:** CERT-In, PCI-DSS 4.0, HIPAA Security Rule, ISO 27001:2022 Annex A, each `met / partial / gap / manual` with evidence.
  Statuses are deliberately conservative: 180-day retention is reported as a **gap** against PCI 10.5.1 (12 months) and HIPAA 164.316 (6 years);
  the mock ledger caps integrity controls at `partial`; NTP is `manual`; transport security (mTLS) is a `gap`.
* **PDF + JSON** with a SHA-256 over the canonical body. `LOGUNIFY_COMPLIANCE_REPORT_INTERVAL_HOURS` writes them on a schedule.
  The PDF writer is dependency-free; its structure is tested, but its rendering has not been eyeballed in a viewer.
* Control texts are paraphrases, not standards wording; have a compliance assessor confirm the mapping before relying on it.
