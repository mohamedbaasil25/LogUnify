# LogUnify deployment runbook (Windows Security + open-source databases)

Every file referenced exists in this repository. Replace the `<...>` values. Nothing here guarantees "no interruption": section 6 lists what is
covered and what is not.

## 1. Data flow

```
WinServer-01 NXLog (to_json) --mTLS--> stunnel :6514 (client cert REQUIRED) --> 127.0.0.1:5514 LogUnify syslog-type TCP listener
Linux DB hosts (rsyslog / filebeat-less tail) --> UDP/TCP source per format (postgresql_log | mysql_error_log | mongodb_log)
   -> parse (YAML parser SDK) -> ECS (event.original = received line; PII-redacted unless archive) -> Drain3 -> Isolation Forest -> MITRE (> 0.7)
   -> Merkle batch (mock Fabric ledger) -> alert rules (score > 0.80 AND critical technique) -> Teams / Slack / email, CERT-In 6 h clock
```

## 2. Settings (`.env`, then `docker compose -f compose.yaml -f deploy/compose.windows-security.yaml up -d backend`)

```bash
LOGUNIFY_AUTH_MODE=jwt                       # never `off` outside a lab
LOGUNIFY_ALERT_SCORE_THRESHOLD=0.80          # provisional, unvalidated (section 8)
LOGUNIFY_ALERT_MAX_NOTIFICATIONS_PER_HOUR=20
LOGUNIFY_ALERT_DEDUP_MINUTES=30
LOGUNIFY_ALERT_TEAMS_WEBHOOK_URL=<https url>      # and/or
LOGUNIFY_ALERT_SLACK_WEBHOOK_URL=<https url>
LOGUNIFY_ALERT_SMTP_HOST=<host>  LOGUNIFY_ALERT_SMTP_PORT=587  LOGUNIFY_ALERT_SMTP_SECURITY=starttls
LOGUNIFY_ALERT_SMTP_USER=<user>  LOGUNIFY_ALERT_SMTP_PASSWORD=<secret>
LOGUNIFY_ALERT_EMAIL_FROM=soc@<domain>  LOGUNIFY_ALERT_EMAIL_TO=<soc-oncall@domain,cert-in-poc@domain>
LOGUNIFY_STATE_HMAC_KEY=$(python3 -c "import secrets;print(secrets.token_urlsafe(48))")   # signs persisted model blobs
LOGUNIFY_RECENT_BUFFER=50000
LOGUNIFY_RAW_ARCHIVE_ENABLED=true            # exact received bytes, AES-256-GCM
LOGUNIFY_RAW_ARCHIVE_KEY=$(python3 -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())")   # back this up: no key, no raw
```
Confirm: `curl -fsS $LU_API/api/v1/alerts/config` shows `0.8` and cap `20`; `curl -fsS $LU_API/ready`.
Test every channel once: `POST /api/v1/alerts/test` (admin) and read the result per channel.

## 3. Transport (mutual TLS, port 6514 -> loopback 5514)

Run `deploy/windows-security/WINSERVER-01.md` blocks A1-A5 and B1-B4 verbatim (certificates, `stunnel-logunify.conf.example`, source creation, NXLog via
`Install-LogUnifyForwarder.ps1`, audit policy via `Set-LogUnifyAuditPolicy.ps1`). Both PowerShell scripts are dry-run unless `-Apply`; neither has been run on
a real Windows host by the author. Required stunnel properties: `verifyChain = yes`, `requireCert = yes`, `CAfile = forwarders-ca.crt`, `accept = 0.0.0.0:6514` (restrict with the firewall rule),
`connect = 127.0.0.1:5514`. Proven locally with synthetic events: valid client cert delivers; no cert / foreign CA / plain TCP deliver nothing.

## 4. Sources and parsers

| Source | Parser (`format`) | Notes |
|---|---|---|
| Windows Security (NXLog `to_json()`) | `windows_security` | timezone `Asia/Kolkata`; tags `["windows","winserver-01"]` |
| PostgreSQL | `postgresql_log` | `log_line_prefix = '%m [%p] %q%u@%d '`, `log_connections=on`; set source `timezone` to the server `log_timezone` |
| MySQL 8 | `mysql_error_log` | `log_error_verbosity=3` to get `Access denied` lines; timestamps carry their own offset |
| MongoDB 4.4+ | `mongodb_log` | JSON log (default); ACCESS component carries auth outcomes |
| Others present | `linux_auditd`, `okta_system_log`, `azure_ad_signin`, `fortinet_fortigate`, `palo_alto_traffic`, `aws_cloudtrail`, `iptables_log`, `nginx_access` | |

Create a source per feed (`POST /api/v1/sources`, admin), e.g.:
```bash
curl -fsS -X POST $LU_API/api/v1/sources -H "Authorization: Bearer $ADMIN_TOKEN" -H 'content-type: application/json' -d '{
 "name":"postgres-prod-01","type":"syslog","protocol":"tcp","port":5515,"format":"postgresql_log","timezone":"UTC","tags":["database","production"]}'
```
Verify parsing on YOUR lines before trusting a parser: `python -m app.parsers.cli try <parser> "<real line>"`, and add the line as a fixture.
CI gate: `python -m app.parsers.cli test --strict` (34/34 at the time of writing; fixtures are hand-made, not real exports).

## 5. Production vs controlled test vs synthetic (what the system actually enforces)

| Class | How it is marked | Effect |
|---|---|---|
| Production | source without the `synthetic` tag | learned by Drain3/IF, counted in calibration |
| Synthetic feed | source tagged `synthetic` (e.g. `scripts/send_windows_samples.py` into a dedicated source) | `labels.synthetic=true`, **excluded from model learning and calibration**, alert subject `[TEST FEED]` |
| Controlled test activity on the real host (`New-LogUnifyDemoActivity.ps1 -Apply`) | **cannot be tagged** (same NXLog source). Marker user `logunify_demo_*`, command-line text `logunify-demo`, manifest in `%ProgramData%\LogUnify\demo-activity-manifest.json` | enters the model like production: keep counts at the script's caps, record the window, exclude it by hand from calibration, restart-clean the model if volume was large |

Rule: send drills only to a source tagged `synthetic`. Never put simulated data in a production source; that is the only way contamination is prevented.

## 6. Resilience: covered vs not covered

Covered (tested): enrichment/alerting failures never drop a log; at-least-once ES forwarder with dead-letter (verified against an in-process stub only);
state persisted (SQLite or Postgres) with signed model blobs; notification cap with summarised overflow; DLQ for unparsable lines.
Not covered / not verified: real Elasticsearch, Flink and Vector images (not built), Windows scripts and NXLog TLS on a real host, a multi-replica shared
source set, certificate expiry (server 730 d, client 365 d: an expired certificate silently stops the feed; calendar it), mock Fabric ledger (not a real ledger).

## 7. Acceptance checks (all must pass before sign-off)

```bash
python3 logunify-backend/scripts/verify_windows_onboarding.py --url $LU_API --token $ANALYST_TOKEN --host winserver-01
curl -fsS $LU_API/api/v1/alerts/config
curl -fsS -H "Authorization: Bearer $ADMIN_TOKEN" $LU_API/api/v1/archive          # encrypted: true
curl -fsS "$LU_API/api/v1/trace/<event.id>"                                         # verdict: verified
cd logunify-backend && python -m pytest tests -q -m "not kafka" && python -m app.parsers.cli test --strict && python scripts/bench_pipeline.py --min-eps 300
```

## 8. Deployment sign-off statement (complete the bracketed facts truthfully; delete what is not true)

> LogUnify has been deployed on [date] for the [Windows Security log of WinServer-01 and the open-source database sources: ...]. Events are received over
> mutual TLS (stunnel, port 6514, client certificates required) and delivered to a loopback listener, parsed, normalised to ECS with the received line
> preserved, scored and tagged with MITRE ATT&CK techniques. Alerts fire when the anomaly score exceeds **0.80** and the technique is critical; notifications
> are capped at 20 per hour and sent via [Teams / Slack / email], supporting the 6-hour CERT-In reporting workflow (LogUnify never files with CERT-In itself).
>
> **The 0.80 threshold is a conservative, unvalidated baseline. It was not derived from measured data on this environment and awaits a 7-day calibration on
> real production traffic.** Until that calibration is completed, alert volumes and false-positive rates are unknown. Test and synthetic data were kept
> separate from production through [the `synthetic` source tag / manifest ...]. Not verified at sign-off: [list from section 6 that still applies].
>
> Signed: [name, role, date]
