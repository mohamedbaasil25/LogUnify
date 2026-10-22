# Onboarding `WinServer-01` (time zone `Asia/Kolkata`, TLS with client certificates)

Run the blocks in order. **Four values are yours to set; everything else is filled in:**

| Variable | Meaning |
|---|---|
| `LU_FQDN` | the DNS name (or IP) `WinServer-01` will use to reach LogUnify, e.g. `logunify.corp.example.com`. It must resolve from `WinServer-01`, and it is baked into the server certificate |
| `LU_API` | the LogUnify API base URL, e.g. `https://logunify.corp.example.com` (or `http://127.0.0.1:8000` on the host) |
| `WIN_IP` | `WinServer-01`'s IP address (for the firewall rule) |
| `ADMIN_TOKEN` / `ANALYST_TOKEN` | bearer tokens for your LogUnify (admin creates the source, analyst runs the checker) |

**Tested here with synthetic events:** certificate generation; the stunnel mutual-TLS terminator (a valid client certificate delivered all events; no certificate, a certificate from another CA,
a client that does not trust the server, and plain TCP to the TLS port delivered nothing); the LogUnify source and listener; the Kolkata time-zone handling; the checker.
**Not run by the author:** the two PowerShell scripts, NXLog's `om_ssl`, and any Windows host. Both scripts are dry-run unless you pass `-Apply`: read the dry-run output first.

---
## A. On the LogUnify host (Linux shell, from the repository root)

**A1. Set the variables and create the certificates** (a private CA, the server certificate for `LU_FQDN`, and a client certificate for `WinServer-01`):
```bash
export LU_FQDN=logunify.corp.example.com          # <- yours
export LU_API=https://logunify.corp.example.com   # <- yours
export WIN_IP=10.0.5.30                           # <- WinServer-01's address

mkdir -p ~/logunify-certs && chmod 700 ~/logunify-certs
OUT=~/logunify-certs deploy/windows-security/make-certs.sh "$LU_FQDN" WinServer-01
ls ~/logunify-certs      # ca.crt ca.key logunify-server.{crt,key} WinServer-01.{crt,key}
```
`ca.key` can mint certificates the listener will accept: after A2, move it to offline storage. Certificates expire (server 730 days, client 365): put the dates in a calendar, an expired
certificate silently stops the feed.

**A2. TLS terminator (stunnel, mutual TLS) in front of the listener:**
```bash
sudo apt-get install -y stunnel4
sudo install -m 0640 -o root -g stunnel4 ~/logunify-certs/logunify-server.crt /etc/stunnel/logunify-server.crt
sudo install -m 0640 -o root -g stunnel4 ~/logunify-certs/logunify-server.key /etc/stunnel/logunify-server.key
sudo install -m 0644 ~/logunify-certs/ca.crt /etc/stunnel/forwarders-ca.crt
sudo install -m 0644 deploy/windows-security/stunnel-logunify.conf.example /etc/stunnel/logunify.conf
sudo systemctl enable --now stunnel@logunify
sudo systemctl status stunnel@logunify --no-pager | head -5
# only WinServer-01 may even reach the TLS port (ufw shown; use your firewall):
sudo ufw allow from "$WIN_IP" to any port 6514 proto tcp
```

**A3. LogUnify settings and start** (compose; the listener is published on loopback only, so stunnel is the only thing facing the network). Append these to `.env`:
```bash
cat >> .env <<ENVEOF
LOGUNIFY_WINDOWS_LISTEN=127.0.0.1
LOGUNIFY_RECENT_BUFFER=50000
LOGUNIFY_SYSLOG_MAX_MESSAGE_BYTES=32768
LOGUNIFY_BACKEND_MEM=2g
LOGUNIFY_STATE_HMAC_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")
ENVEOF
# also set at least one alert channel in .env, otherwise alerts are only recorded and nobody is told:
#   LOGUNIFY_ALERT_SLACK_WEBHOOK_URL=...   or   LOGUNIFY_ALERT_TEAMS_WEBHOOK_URL=...

docker compose -f compose.yaml -f deploy/compose.windows-security.yaml up -d backend
curl -fsS "$LU_API/ready" && echo " ready"
```
Not using compose? Set the same `LOGUNIFY_*` variables for your service, plus `LOGUNIFY_SYSLOG_BIND=127.0.0.1`.

**A4. Create the source** (admin token; it binds TCP 5514 now and again after every restart):
```bash
curl -fsS -X POST "$LU_API/api/v1/sources" -H "Authorization: Bearer $ADMIN_TOKEN" -H 'content-type: application/json' -d '{
  "name": "windows-security-winserver-01", "type": "syslog", "protocol": "tcp", "port": 5514,
  "format": "windows_security", "timezone": "Asia/Kolkata", "tags": ["windows", "calibration", "winserver-01"] }'
```
(With `auth_mode=off`, drop the `Authorization` header.)

**A5. Prove TLS works from the Linux side before touching Windows** (expect `Verification: OK`):
```bash
openssl s_client -connect "$LU_FQDN:6514" -servername "$LU_FQDN" -CAfile ~/logunify-certs/ca.crt \
  -cert ~/logunify-certs/WinServer-01.crt -key ~/logunify-certs/WinServer-01.key -verify_return_error -verify_hostname "$LU_FQDN" </dev/null 2>&1 \
  | grep -E "Verification|Verify return"
```

---
## B. On `WinServer-01` (PowerShell **as Administrator**)

**B1. Get the files onto the server** (any secure way, e.g. `scp` from the LogUnify host): `ca.crt`, `WinServer-01.crt`, `WinServer-01.key`, and the files from `deploy/windows-security/`:
`Set-LogUnifyAuditPolicy.ps1`, `Install-LogUnifyForwarder.ps1`, `nxlog.conf.template`.
```powershell
New-Item -ItemType Directory -Force 'C:\Program Files\nxlog\cert' | Out-Null
# put ca.crt, WinServer-01.crt and WinServer-01.key into C:\Program Files\nxlog\cert\ , then lock the private key:
icacls 'C:\Program Files\nxlog\cert\WinServer-01.key' /inheritance:r /grant:r 'SYSTEM:R' 'Administrators:R'

New-Item -ItemType Directory -Force 'C:\LogUnifyPack' | Out-Null
# put the two .ps1 files and nxlog.conf.template into C:\LogUnifyPack , then:
Get-ChildItem C:\LogUnifyPack | Unblock-File
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
cd C:\LogUnifyPack
```

**B2. Audit settings: dry run, read it, then apply** (Logon / Logoff / Special Logon / Account Lockout / User Account and Security Group Management / Process Creation with command line /
Audit Policy Change / Security System Extension, and a 512 MB Security log):
```powershell
.\Set-LogUnifyAuditPolicy.ps1             # prints the current state and what it would run; changes nothing
.\Set-LogUnifyAuditPolicy.ps1 -Apply
```
If `WinServer-01` is domain-joined, a Group Policy that sets audit policy overrides this at the next refresh: put the same settings in a GPO for anything beyond a pilot.
On a non-English Windows each `auditpol` call reports an error (the subcategory names are English).

**B3. Install NXLog** (Community Edition MSI from https://nxlog.co/downloads, default location `C:\Program Files\nxlog`), then **the forwarder configuration: dry run, then apply:**
```powershell
$LU   = 'logunify.corp.example.com'           # <- the same LU_FQDN as above
$cert = 'C:\Program Files\nxlog\cert'
.\Install-LogUnifyForwarder.ps1 -LogUnifyHost $LU -Port 6514 -Tls -CaFile "$cert\ca.crt" -CertFile "$cert\WinServer-01.crt" -KeyFile "$cert\WinServer-01.key"
.\Install-LogUnifyForwarder.ps1 -LogUnifyHost $LU -Port 6514 -Tls -CaFile "$cert\ca.crt" -CertFile "$cert\WinServer-01.crt" -KeyFile "$cert\WinServer-01.key" -Apply
```
`-Apply` backs up the old `nxlog.conf`, writes the new one, validates it with `nxlog.exe -v`, and restarts the service.

**B4. Look at NXLog, and make a few events happen:**
```powershell
Get-Service nxlog
Get-Content 'C:\Program Files\nxlog\data\nxlog.log' -Tail 30        # connection / certificate errors show up here
Test-NetConnection $LU -Port 6514                                    # TcpTestSucceeded : True
# generate events: a failed logon (4625) and a normal one (4624 / 4634 / 4672)
runas /user:doesnotexist cmd                 # type any password: logs a 4625
rundll32.exe user32.dll,LockWorkStation      # lock, then unlock again (needs a console / RDP session)
```

---
## C. Verify (about 10 minutes after B3, and again after 24 hours)
```bash
python3 logunify-backend/scripts/verify_windows_onboarding.py --url "$LU_API" --token "$ANALYST_TOKEN" --host winserver-01
```
Expect PASS for service, source, host connected, events received, no loss, parsed fields and time zone. A WARN on "buffer horizon" is normal until it has 10+ minutes of data; read it at 24 hours:
it tells you how many days of events the 50,000 buffer really holds at `WinServer-01`'s rate.

| Result | Meaning / fix |
|---|---|
| `host connected` FAIL | nothing reached the listener: `Test-NetConnection` from Windows; the firewall rule (A2); `journalctl -u stunnel@logunify` (a rejected handshake means a wrong CA, an expired certificate, or a name that does not match `LU_FQDN`); the NXLog log (B4) |
| `time zone` FAIL | the gap between event time and ingest time is a whole UTC offset: the source's `timezone` does not match the server's zone (`Get-TimeZone` on the server; Kolkata is `India Standard Time`) |
| `parsed fields` FAIL | NXLog names a field differently from the parser: send me one line (from a captured event or `nxlog.log`) |
| `no loss` FAIL | lines were dropped or dead-lettered: oversize (raise `LOGUNIFY_SYSLOG_MAX_MESSAGE_BYTES`) or unparsable (`GET /api/v1/dlq`, admin) |
| `event mix` WARN | unwanted event IDs dominate: tighten the query in `nxlog.conf.template` and re-run B3 |

## D. After it is running
* Days 1-3: leave it alone and do not tune. Day 3 onward: dashboard **Calibration**, Source = `windows_security` (`logunify-backend/docs/WINDOWS_SECURITY.md`, section 8).
* More Windows hosts: bring `ca.key` back, run `OUT=~/logunify-certs deploy/windows-security/make-certs.sh "$LU_FQDN" WinServer-02` (the CA and server certificate are reused), repeat B1-B4 with that
  host's files, and either reuse this source (same port, format and time zone) or create one per host.
* Revoking a host: stunnel trusts the CA, so a stolen client certificate stays valid until it expires. Either re-issue everything from a new CA, or add a CRL (`CRLfile` in the stunnel config).
