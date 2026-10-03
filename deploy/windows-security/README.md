# Windows Security onboarding pack

Everything needed to put ONE Windows host's Security log into LogUnify. Start with the go-live table in
[`logunify-backend/docs/WINDOWS_SECURITY.md`](../../logunify-backend/docs/WINDOWS_SECURITY.md) (section 0).

| File | Runs on | Purpose |
|---|---|---|
| `env.example` | LogUnify host | settings for the source (buffer, message size, HMAC key, listener address, alert channels) |
| `../compose.windows-security.yaml` | LogUnify host | compose overlay: publishes the TCP listener on a private address |
| `WINSERVER-01.md` | both | **ready-to-run commands for `WinServer-01` (Asia/Kolkata, TLS)**: start here |
| `make-certs.sh` | LogUnify host | private CA + server certificate + one client certificate per Windows host (PEM; reuses the CA to add hosts) |
| `stunnel-logunify.conf.example` | LogUnify host | mutual-TLS terminator in front of the listener (which has no TLS / auth) |
| `Set-LogUnifyAuditPolicy.ps1` | Windows host | audit subcategories, command-line auditing, Security log size. **Dry run unless `-Apply`** |
| `nxlog.conf.template` + `Install-LogUnifyForwarder.ps1` | Windows host | NXLog config (event-ID filter, JSON, disk buffer, TCP or TLS) and its installer. **Dry run unless `-Apply`** |
| `../../logunify-backend/scripts/verify_windows_onboarding.py` | anywhere | health check of the running feed (PASS / WARN / FAIL) |
| `../../logunify-backend/scripts/send_windows_samples.py` | scratch instance only | SYNTHETIC events for smoke tests. Never send them to the instance you calibrate on |

Verified by the author: certificate generation and the mutual-TLS terminator end to end (a valid client certificate delivered; no certificate / foreign-CA certificate / untrusting client / plain TCP delivered nothing), and the merged compose configuration.
Not verified by the author: the PowerShell scripts, the NXLog configuration and the stunnel configuration (no Windows host, NXLog or stunnel available here). The LogUnify side
(listener, parser, time zone handling, rules, search, calibration, restart, the checker) was run end to end with synthetic events.
