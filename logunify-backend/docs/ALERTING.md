# Critical alerting and the CERT-In 6-hour workflow

When a log's anomaly score **exceeds 0.9** *and* it matches a **critical MITRE ATT&CK technique**, LogUnify raises a
high-priority alert by **signed webhook and/or email**. Each alert carries a **CERT-In incident report draft** (form-aligned, with the
6-hour deadline), tracks the deadline with reminders, and records who acknowledged, reported and closed it.

```
Pipeline.process ─► AlertRules (score > 0.9 AND rule-matched critical technique)
                        │ yes
                        ▼
   durable alert (SQLite, audit trail) ─► queue ─► webhook ─┐   retries with backoff, per channel
   6-hour clock starts NOW                         └► email ─┘   failed channels retried until someone reports/closes
                        │
   maintenance loop: deadline reminders (2h/1h/30m) → overdue notices → storm summaries
                        │
   analyst: ack → add details → verify report → SUBMIT TO CERT-IN THEMSELVES → mark reported (who, how, when, reference)
```

**LogUnify never files with CERT-In by itself.** An automated score is not a legal determination; a false positive sent to a
regulator has consequences. A human verifies the draft, submits it, and records the submission.

## 1. What CERT-In actually requires

Read from the primary documents: [Directions No. 20(3)/2022-CERT-In, 28 Apr 2022](https://www.cert-in.org.in/PDF/CERT-In_Directions_70B_28.04.2022.pdf),
the [Incident Reporting Form](https://www.cert-in.org.in/PDF/certinirform.pdf), and the
[FAQ, May 2022](https://www.cert-in.org.in/PDF/FAQs_on_CyberSecurityDirections_May2022.pdf).

**Important nuance about "mandatory fields":** the official form states that it is *general guidance*, that filling it is *not
mandatory*, and that an incident may be reported "in any other readable form". What is legally mandatory is reporting the
Annexure I incident types within 6 hours of noticing them, and providing logs with the report. So this module fills **every field
the official form asks for that the platform can know**, lists the rest as gaps for a human, and does not claim any field is
legally "mandatory".

| Requirement | Source | How the module handles it |
|---|---|---|
| Report Annexure I incidents **within 6 hours of noticing** | Directions para (ii); FAQ Q24 | `report_due_at = created_at + 6 h`; the clock starts when LogUnify raises the alert (automated detection = noticing); reminders at 2 h / 1 h / 30 min; overdue notices hourly |
| Report by email `incident@cert-in.org.in`, phone 1800-11-4949, fax 1800-11-6969 | Directions para (ii), Annexure I | Printed in every report |
| The 20 incident types | Annexure I | Controlled vocabulary (`cert_in.ANNEXURE_I`); a type is **suggested** from the technique, an analyst confirms |
| Report what you have, complete later | FAQ Q30 | `completeness` block lists gaps; missing items never stop the clock |
| Which incidents need the 6-hour report | FAQ Q30 criteria | Shown as an analyst checklist; closing as `not_reportable` requires a written reason |
| Logs accompany the report | Directions para (iv) | `GET /alerts/{id}/evidence`: full record + SHA-256 + Merkle batch / ledger anchor reference |
| Designated Point of Contact | Directions para (iii), Annexure II | Reporter block from `LOGUNIFY_POC_*` |
| Clocks synced to NIC/NPL NTP | Directions para (i) | Operational: sync the LogUnify host; reports give IST (dd/mm/yyyy hh:mm, as the form asks) and UTC |
| Whoever notices the incident must report; not transferable | FAQ Q13 | `i_am` field; alert ownership is the reporter's |
| Customer-data confidentiality duties unchanged | FAQ Q32 | Notifications carry a **redacted**, truncated excerpt; the unredacted record is behind the API key |

This is our reading of public documents, not legal advice: confirm scope (who is an obligated entity, which incidents qualify) with counsel.

## 2. The trigger (and an honest calibration finding)

An alert needs **all** of:
1. `logunify.anomaly.score` **strictly greater than** `LOGUNIFY_ALERT_SCORE_THRESHOLD` (0.9) and the model is warmed up;
2. a technique in `LOGUNIFY_ALERT_CRITICAL_TECHNIQUES` (a parent id such as `T1070` also covers `T1070.001`);
3. that technique was chosen by a **rule** (`logunify.mitre.basis = rule:<name>`), not the placeholder fallback.

Point 3 matters: the tagger falls back to **T1078 for any log above 0.7** when no rule matches. Matching on that fallback would make the
"critical technique" condition meaningless (roughly 70 % of all tagged logs in our runs), so it is ignored unless
`LOGUNIFY_ALERT_REQUIRE_RULE_BASIS=false`. The rules (`app/intel/mitre.py`) are conservative keyword/field heuristics:
log clearing, credential dumping, ransomware, shadow-copy deletion, exfiltration, web exploitation, C2, command execution, privileged-group
changes, external login. **They are heuristics, not validated detections**; each report says so.

Default critical set: T1003, T1021, T1041, T1048, T1059, T1068, T1070, T1071, T1078, T1098, T1133, T1190, T1485, T1486, T1490, T1562, T1567.
**T1110 (brute force) is deliberately excluded**: on internet-facing hosts it is constant background noise.

**Calibration finding: a 0.9 threshold is almost unreachable with the current model.** On ~58,000 generated logs
(`python scripts/alert_threshold_survey.py --logs 60000`; synthetic traffic with a few rare events, so directional only):

| threshold | alerts (after grouping) |
|---|---|
| 0.90 (as requested) | **0** |
| 0.85 | 2 |
| 0.80 | 6 |
| 0.75 | 10 |
| 0.70 | 15 |

Only 5 of 29,000 logs scored above 0.9 in a separate run, and all 5 carried the placeholder fallback tag. The 0.9 default is kept because
you specified it, but with it the module will rarely or never fire until the scoring model is improved or the threshold lowered.
Run the survey on a sample of **your** traffic and choose the lowest threshold whose volume your analysts can triage inside 6 hours.

## 3. Alert lifecycle

`open` → `acknowledged` → `reported` → `closed`. Acknowledging does **not** stop the clock; only reporting (or closing as false positive /
not reportable) does. Rules that protect the record:
- `resolved` is only allowed after `reported` (an incident cannot be "resolved" without the report being recorded);
- `false_positive` / `not_reportable` need a reason of 10+ characters, and are not allowed once reported;
- `reported` records who, how (email/phone/fax/portal/other), when, CERT-In's reference, and whether it was **on time**; a late report records how late;
- every step is an **append-only audit event** (SQLite triggers reject UPDATE/DELETE) with actor and client address.

Noise control: repeats of the same technique on the same asset are **counted, not re-sent** while activity continues (quiet period 30 min);
a hard cap (default 20/hour) on first notifications protects the channels. Overflow alerts are recorded, appear in the API, and are announced in **one**
summary message; their deadline reminders still go out. Nothing is dropped.

Reliability: the alert is saved (clock started) **before** any notification; each channel retries with exponential backoff (4 attempts), then keeps being
retried by the maintenance loop (backoff to 15 min) until the alert is reported or closed. Permanent errors (HTTP 4xx, SMTP 5xx, STARTTLS missing) are
not hammered, but are recorded and surfaced. Open alerts and their clocks **survive a restart** (verified in a live run).

## 4. The CERT-In report: where each form field comes from

`GET /api/v1/alerts/{id}/cert-in-report` (`?format=text` for a paste-ready email body). Marked `DRAFT`.

| Official form field | Filled from | Notes |
|---|---|---|
| I am (affected entity / reporting for another) | analyst, default "the affected entity" | |
| Reporter name & role, organization, contact no., email, address | configuration `LOGUNIFY_POC_*`, `LOGUNIFY_ORG_*` | blank + flagged `[CONFIG]` if unset; never invented |
| Affected entity | analyst, else organization name | |
| Incident type (Annexure I) | **suggested** from the MITRE technique; analyst can override | always listed under "to confirm" |
| Critical to the organization's mission? | analyst, else `LOGUNIFY_ORG_CRITICAL_ASSETS` match | `[ANALYST]` if unknown |
| Domain/URL | log fields (`url.*`, `destination.domain`) | |
| IP address | derived: the internal side of the event | a lone external IP is the **remote party**, not the victim |
| Operating system, make/model/cloud, affected application | `host.os.*` / `service.name` / `process.name`, else analyst | usually `[ANALYST]` |
| Location (city, region, country), network/ISP | analyst, else `LOGUNIFY_ORG_LOCATION` / `_ISP` | config defaults are flagged "confirm" |
| Brief description | generated (score, technique, redacted excerpt) + analyst addendum | |
| Occurrence date & time, detection date & time (dd/mm/yyyy hh:mm) | log `@timestamp` / alert creation | IST and UTC; warns when the log had no timestamp or no year/timezone |
| *(additional)* evidence, detection details, remote party, reportability checklist, data-quality warnings | pipeline | demo GeoIP and demo threat-intel matches are **omitted and flagged**, never shown to a regulator |

Analysts fill gaps with `PATCH /api/v1/alerts/{id}/details`.

## 5. Notifications

**Webhook** (`LOGUNIFY_ALERT_WEBHOOK_URL`, https; plain http only for loopback): `POST` JSON
`{"schema":"logunify.alert/v1","event":"incident.detected|incident.reminder|incident.overdue|incident.storm|test","severity":"critical","text":"one line","alert":{…},"cert_in_report":{…}}`.
Headers: `X-LogUnify-Event`, `X-LogUnify-Alert-Id`, `X-LogUnify-Delivery` (unique per attempt), `X-LogUnify-Timestamp`, and
`X-LogUnify-Signature: v1=<hmac>`. Redirects are never followed. The URL is never logged beyond `scheme://host` (chat webhook paths are credentials).
Delivery is at-least-once: dedupe on `alert.id` + `event`.

Verify on the receiver (the timestamp is signed, so a captured request cannot be replayed later):

```python
import hmac, hashlib, time
def verify(secret: str, headers, raw_body: bytes, tolerance: int = 300) -> bool:
    ts, sig = headers["X-LogUnify-Timestamp"], headers["X-LogUnify-Signature"]      # sig = "v1=<hex>"
    if abs(time.time() - int(ts)) > tolerance:
        return False
    expected = "v1=" + hmac.new(secret.encode(), f"{ts}.".encode() + raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig)
```

**Email** (`LOGUNIFY_ALERT_SMTP_*`): STARTTLS by default and **never silently downgraded** (a server without STARTTLS is an error); `ssl` supported; plaintext only for
loopback. High-importance headers, plain-text body with the report, JSON report attached. Subjects are sanitised (log-derived text cannot inject headers);
recipients come from configuration only. Point `LOGUNIFY_ALERT_EMAIL_TO` at internal addresses; adding `incident@cert-in.org.in` would auto-submit unreviewed drafts, which is not recommended.

Misconfiguration fails **at start-up** (bad technique id, bad email, http webhook to a remote host, half-configured SMTP, reminder outside 1-359 min).
`POST /api/v1/alerts/test` sends a clearly-labelled TEST through every channel (no alert, no clock).

## 6. API (all require `X-API-Key`; unset `LOGUNIFY_ALERT_API_KEY` = API disabled)

| Endpoint | Purpose |
|---|---|
| `GET /api/v1/alerts?status=active\|open\|acknowledged\|reported\|closed` | list, with seconds remaining and overdue flag |
| `GET /api/v1/alerts/{id}` · `/cert-in-report[?format=text]` · `/evidence` · `/events` | detail · report · unredacted record + hash + Merkle reference · audit trail |
| `POST …/ack` · `PATCH …/details` · `POST …/report` · `POST …/close` | the human workflow (each needs `by`) |
| `GET /api/v1/alerts/config` · `POST /api/v1/alerts/test` | effective config (no secrets) · channel check |

`/api/v1/metrics` gains an `alerting` block (per-process counters: triggered, suppressed, open, overdue, notification ok/failed, rate-limited).

## 7. Configuration

All `LOGUNIFY_`-prefixed; see `.env.example`. Key settings: `ALERT_SCORE_THRESHOLD` (0.9), `ALERT_CRITICAL_TECHNIQUES`, `ALERT_REQUIRE_RULE_BASIS` (true),
`ALERT_DEDUP_MINUTES` (30), `ALERT_MAX_NOTIFICATIONS_PER_HOUR` (20), `ALERT_REMINDER_MINUTES` (120,60,30), `ALERT_OVERDUE_REPEAT_MINUTES` (60),
`ALERT_RETRY_ATTEMPTS` (4), `ALERT_DB_PATH` (data/alerts.db, created on the first alert, mode 0600 where supported), `ALERT_API_KEY`,
`ALERT_WEBHOOK_*`, `ALERT_SMTP_*`, `ALERT_EMAIL_FROM/TO`, `ORG_*`, `POC_*`.

## 8. Runbook for the on-call analyst

1. **T+0** alert arrives (the clock is running). Acknowledge (`ack`) within minutes.
2. **Decide reportability** with the FAQ Q30 checklist. If not reportable: `close` as `not_reportable` with the reason. If a false positive: `false_positive` with evidence.
3. **Complete the draft**: confirm the incident type and affected system, add OS / critical-asset answer / impact / actions (`PATCH …/details`).
4. **Submit within 6 hours**: email the text report plus the evidence to incident@cert-in.org.in (or phone/fax). Missing items are acceptable (FAQ Q30): send what you have.
5. `report` to record how and when (and CERT-In's reference). Send further information later as it becomes available.
6. After containment, `close` as `resolved`.

Operate it like any compliance control: back up `alerts.db` (audit trail) to WORM storage, keep host clocks NTP-synced to NIC/NPL, rotate the API key and webhook secret, and rehearse with `POST /alerts/test`.

## 9. What was verified, and what was not

**Verified** (205 backend tests + live runs): trigger boundary (0.9 not enough, 0.9001 fires), sub-technique matching, fallback-tag exclusion, malformed input never raising;
redaction (including a leak found and fixed: Drain3 templates hold literal values); report fields, IST formatting, 6-hour arithmetic, completeness, demo-data omission;
deduplication, retries/backoff, partial-channel retry, rate cap + summary, reminders/overdue with an injected clock, transitions and audit trail, restart restoration;
webhook signing/verification and error classification (mock transport), real SMTP conversations (header injection, no STARTTLS downgrade, 4xx/5xx handling);
API auth and workflow; and a **live run**: real backend process, real HTTP webhook (with simulated 503s and valid signatures), real SMTP, a restart with clocks continuing, and reminders across the restart.
The live run also exposed two bugs that unit tests had not (a lone external address reported as the victim; a missing source timestamp presented as the occurrence time), both fixed and pinned by tests.

**Not verified / known limits**
- Not tested against a real SMTP relay (TLS/AUTH), Slack/Teams/SOAR endpoints, or CERT-In itself.
- The MITRE mapping is heuristic. First-seen **free-text** events (the ones anomaly detection favours) have sparse fields: the affected host is often unknown and the report says so.
- At the requested 0.9 threshold the module will rarely fire on current scoring (see section 2).
- Single-instance design (in-process queue, local SQLite); counters reset on restart (the alert database is the durable record). Reminder granularity is the maintenance interval (60 s).
- `alerts.db` is never purged (alert records and their audit trail are compliance evidence: apply your own retention policy, and set an **absolute** `LOGUNIFY_ALERT_DB_PATH` on a backed-up volume; the default is relative to the working directory). The hourly notification cap limits messages, not stored alerts.
- The alert API uses one shared key; the rest of the LogUnify API remains unauthenticated (unchanged). Put it behind your gateway/SSO for production.
- CERT-In FAQ Q35 says logs may be stored outside India if they can be produced to CERT-In reasonably quickly, while Directions para (iv) says "within the Indian jurisdiction"; confirm your position with counsel.
