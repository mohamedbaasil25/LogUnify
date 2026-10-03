# Onboarding the Windows Security log (first real source)

Goal: get one Windows host's Security log into LogUnify cleanly, long enough to **calibrate alerts on real traffic** (dashboard `/calibration`).
Start with ONE host (the elevated / admin host you care about), not a domain controller: a DC produces orders of magnitude more events.

**Verification status.** Everything on the LogUnify side (listener, parser, timezone handling, event-ID rules, search, calibration, restart
restore) was run end to end here with *synthetic* events (`scripts/send_windows_samples.py`). The Windows side (audit policy, NXLog) is written
from the vendors' documentation and **has not been run against a real Windows host or NXLog**. Check one real event against the parser first (step 5).

## 1. Data path

```
Windows host ── NXLog (im_msvistalog, to_json) ── TCP, newline-delimited JSON ──► [TLS terminator] ──► LogUnify TCP listener (syslog-type source,
                                                                                                          format=windows_security, timezone=<host zone>)
```
* The listener frames by newline (a line starting with `{` is never mistaken for octet counting). One event per line, up to `LOGUNIFY_SYSLOG_MAX_MESSAGE_BYTES`.
* **The listener has no TLS and no authentication.** Windows event data (user names, IPs, process command lines) must not cross a network in clear text:
  run it on a private/VPN segment, or put a TLS terminator in front (stunnel / nginx `stream` / HAProxy) and have NXLog use `om_ssl`. Do not expose the port to untrusted networks.
* Supported input: **NXLog `to_json()` field names** (`EventTime`, `Hostname`, `EventID`, `Channel`, `SourceName`, `TargetUserName`, ...). Winlogbeat's nested `winlog.*`
  format and raw EVTX/XML are **not** supported by this parser (convert at the shipper, or ask for a second parser).

## 2. Windows side

**Audit policy** (Advanced Audit Policy Configuration; without it the events are never written):

| Subcategory | Events you get |
|---|---|
| Logon / Logoff / Special Logon | 4624, 4625, 4634, 4647, 4648, 4672 |
| Account Lockout | 4740 |
| User Account Management / Security Group Management | 4720, 4726, 4728, 4732, 4756 |
| Process Creation (+ GPO "Include command line in process creation events") | 4688 with `CommandLine` |
| Audit Policy Change | 4719 |
| Security System Extension | 4697 |
| (always on) log cleared | 1102 (Security), 104 (System) |
| Service installed (System log) | 7045 |

**Do not collect** the high-volume, low-value IDs: 5156/5158/5152 (Filtering Platform), 4656/4658/4663 (object access), 4670, 4690, 4703, 4798/4799. They would fill the
buffer and teach the model nothing useful. Collect only the IDs above to start.

**NXLog** (from NXLog's documentation; not tested here):
```
<Extension _json>
    Module  xm_json
</Extension>

<Input eventlog>
    Module  im_msvistalog
    <QueryXML>
      <QueryList>
        <Query Id="0">
          <Select Path="Security">*[System[(EventID=1102 or EventID=4624 or EventID=4625 or EventID=4634 or EventID=4647 or
            EventID=4648 or EventID=4672 or EventID=4688 or EventID=4697 or EventID=4719 or EventID=4720 or EventID=4726 or
            EventID=4728 or EventID=4732 or EventID=4740 or EventID=4756)]]</Select>
          <Select Path="System">*[System[(EventID=104 or EventID=7045)]]</Select>
        </Query>
      </QueryList>
    </QueryXML>
    Exec    to_json();
</Input>

<Output logunify>
    Module  om_tcp            # use om_ssl + CAFile for TLS to your terminator
    Host    logunify-or-tls-proxy.example.internal
    Port    5514
</Output>

<Route security_to_logunify>
    Path    eventlog => logunify
</Route>
```
`EventTime` in NXLog's JSON is **the host's local time without an offset**: that is why the LogUnify source takes the host's IANA time zone (step 4). If the host's
zone is wrong, every timestamp (and every time-range search / replay) is shifted. Keep Windows time synced (CERT-In: NTP to NIC/NPL).

**Estimate the event rate before sizing anything** (PowerShell, on the host; run it for a representative hour):
```powershell
$ids = 1102,4624,4625,4634,4647,4648,4672,4688,4697,4719,4720,4726,4728,4732,4740,4756
(Get-WinEvent -FilterHashtable @{LogName='Security'; Id=$ids; StartTime=(Get-Date).AddHours(-1)} -ErrorAction SilentlyContinue | Measure-Object).Count
```
Events per hour × 24 = events per day.

## 3. LogUnify side

| Setting | Value | Why |
|---|---|---|
| `LOGUNIFY_RECENT_BUFFER` | `50000` (see sizing) | events held for search AND for the calibration replay |
| `LOGUNIFY_STATE_PERSIST_LOGS` | `true` (default) | the buffer survives a restart (saved incrementally) |
| `LOGUNIFY_STATE_HMAC_KEY` | a 32+ byte secret | persists the learned Drain3 templates + Isolation Forest window; without it the model re-learns after every restart |
| `LOGUNIFY_SYSLOG_BIND` | the internal interface (`0.0.0.0` inside a container) | default is loopback only |
| `LOGUNIFY_SYSLOG_MAX_MESSAGE_BYTES` | `32768` | `4688` command lines and long messages exceed the 8 KiB default; oversize lines are dropped (counted) |
| `LOGUNIFY_ALERT_API_KEY` / auth | as per your deployment | alert + calibration APIs |
| `LOGUNIFY_ALERT_SLACK_WEBHOOK_URL` or Teams / SMTP | at least one | otherwise alerts are only recorded, nobody is told |

Containers: `docker compose -f compose.yaml -f deploy/compose.windows-security.yaml up -d` publishes the listener port on a host address you choose and passes the settings through.

## 4. Create the source (admin)
```bash
curl -s -X POST https://<logunify>/api/v1/sources -H "Authorization: Bearer $ADMIN_TOKEN" -H 'content-type: application/json' -d '{
  "name": "windows-security-host1", "type": "syslog", "protocol": "tcp", "port": 5514,
  "format": "windows_security", "timezone": "Asia/Kolkata", "tags": ["windows", "calibration"] }'
```
`format` is pinned to `windows_security` so a malformed line is dead-lettered (and counted) instead of falling through to another parser. The port is bound immediately and again after every restart.

## 5. Verify with ONE real event before trusting anything
1. On the host, capture a real line from NXLog (a 4624 and a 4625 are enough) and run it through the parser:
   `python -m app.parsers.cli try windows_security '<the JSON line>'`
2. Check that these fields are filled: `host.name`, `event.code`, `user.name`, `source.ip` (for network logons), `@timestamp` (correct UTC), `event.outcome`, `event.category`.
   A missing field means NXLog named it differently: adjust `app/parsers/builtin/windows_security.yaml` (fields map `path:` / `first_of:`) and add the real line as a fixture in
   `parser_fixtures/windows_security/` (`python -m app.parsers.cli test --update`, then review the expected file by hand).
3. After the feed is live: `GET /api/v1/sources/listeners` (`tcp_received` rising, `connections_total` ≥ 1), `GET /api/v1/metrics` (`dropped`, `dead_lettered` should be 0), the dashboard Search page
   with Parser = `windows_security`, and `GET /api/v1/dlq` (anything dead-lettered is a line the parser could not read).

## 6. Sizing (measured here, one synthetic run; your hardware and events differ)

| 50,000 buffered events | measured |
|---|---|
| process memory | ~390 MB more than idle (about 8 KB per held event: the buffer plus the Merkle batches that keep their records for proofs) |
| state file | ~104 MB (about 2 KB per event, incremental; the file does not shrink by itself) |
| flush after new events | ~15 ms (it rewrote the whole buffer every 5 s before the incremental change: 570 ms and a 115 ms loop stall at only 10,000 events) |
| restart | ready in ~5 s with all 50,000 events, the source and the models restored |
| calibration replay / search | ~0.4 s / 0.1-0.9 s over 50,000 events |
| ingest | 50,000 events through the TCP listener with 0 dropped (about 1,200 events/s on a shared sandbox core) |

Give the backend **at least 1.5 GB** of memory for a 50,000 buffer.

**How long does 50,000 events last?** `buffer ÷ events per day`. At 5,000 events/day that is 10 days; at 50,000/day it is 1 day; at a DC's 1,000,000+/day it is about an hour and the replay
can never reach the "medium / high confidence" bar (24 h / 72 h). The Calibration page rates confidence from the window it actually holds. If your rate is too high for the buffer:
collect fewer event IDs, calibrate on a quieter host first, or raise the buffer (memory grows ~8 KB/event). A compact, longer-lived score history is the next piece to build if you need weeks on a busy source.

## 7. What alerts can fire on Windows events
Event-ID rules (language independent, `app/intel/mitre.py`), only for events scoring above the **tagging** threshold (0.7), then above the **alert** threshold:

| Event | Technique | Rule |
|---|---|---|
| 1102, 104 (log cleared) | T1070.001 | `win_log_cleared` |
| 4728 / 4732 / 4756 adding to Domain/Enterprise/Schema Admins, Administrators, Account/Server/Backup Operators, DnsAdmins (by name or well-known SID) | T1098 | `win_privileged_group_add` |
| 4719 (audit policy changed) | T1562.002 | `win_audit_policy_changed`: **expect false positives** (Group Policy refreshes); a likely suppression/threshold candidate |
| 4625 (failed logon) | T1110 | `auth_failure`, not in the default critical set (background noise) |
| 4624 from an external address | T1078 | `external_login` (critical by default) |
| 4688 command lines with `mimikatz`, encoded PowerShell, `vssadmin delete shadows`, `wevtutil cl` ... | T1003 / T1059 / T1490 / T1070 | keyword rules on the message (needs the command-line GPO) |

Not covered yet: account creation (4720), service install (7045, 4697), scheduled tasks (4698), Kerberos / NTLM events (4768-4776), PowerShell script-block logging (4104). They are parsed and searchable but raise no alert.
**The rules are heuristics, not validated detections.**

## 8. Calibration routine (days 1-14)
1. Days 1-3: let it collect. Do not tune yet. Watch `dropped` / `dead_lettered` and the listener stats.
2. Open `/calibration`, scope Parser = `windows_security`. Read the **funnel**: where does the count collapse? With the default 0.9 threshold it is usually "score above": the model rarely scores that high (in the synthetic run every rare critical event scored 0.71-0.89, never above 0.9; 0.85 gave a handful of alerts per day). Treat that as a hypothesis to test on your data, not a result.
3. Preview the candidate threshold (type it in, **Run replay**) and read the sample rows. Are they things you would act on?
4. Close real alerts with honest resolutions for a week. After ~20 closed alerts the false-positive rates mean something.
5. Change `LOGUNIFY_ALERT_SCORE_THRESHOLD` (and, if needed, `LOGUNIFY_ALERT_CRITICAL_TECHNIQUES`) in configuration and restart. Add suppression rules only for causes a person has confirmed (an admin, with a reason and an expiry).

## 9. Before real data: remove synthetic data
`scripts/send_windows_samples.py` exists to smoke-test the path. Never point it at the instance you calibrate on; if you did, delete the source, stop the service, remove `state.db` (and the alert DB if
alerts were raised), and start clean.
