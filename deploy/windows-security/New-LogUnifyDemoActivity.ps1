<#
.SYNOPSIS
  Causes a SMALL, bounded amount of REAL Windows security events on this host, to demonstrate that auditing -> NXLog -> LogUnify -> parsing -> alerting works.
  DRY RUN by default: nothing happens unless you pass -Apply.

.DESCRIPTION
  What it does (and nothing else):
    * N failed network logons against this machine for a user name that does NOT exist (event 4625; no real account is touched, so nothing can be locked out).
    * M harmless process starts: hostname, whoami, a cmd echo (event 4688 when process-creation auditing with command line is on).
    * Optionally ONE harmless encoded PowerShell command (-EncodedCommand, prints a sentence): exercises LogUnify's encoded-PowerShell keyword rule.
  What it deliberately does NOT do: clear any log, change audit policy, create or modify accounts or groups, touch services, the registry or the network.
  Those events (1102, 4719, 4728 ...) must be drilled with the synthetic feed or on a disposable lab VM, never on a real server.

  HONESTY NOTES (read before putting these events in a report)
    * The events are genuine OS audit events, but they exist because YOU caused them. They prove the pipeline works; they are NOT normal traffic, NOT a baseline,
      and say nothing about false-positive rates. Do not use them to calibrate the alert threshold, and describe them as "controlled test activity".
    * They go through the same NXLog source as real events (they cannot be tagged), so keep the counts small (hard caps below) and keep the manifest: it records the exact
      time window and the markers (user name prefix logunify_demo, command-line marker logunify-demo) so they can be found, and excluded from any analysis.
    * Repeated failed logons and encoded PowerShell look like attacks to AV / EDR / SOC tooling. Tell your security team first.
    * An alert is NOT guaranteed: LogUnify alerts only when the anomaly score exceeds the threshold AND the technique is critical. Parsing and field mapping are the dependable part.

  Refuses to run on a domain controller, with -Apply twice within 10 minutes, or with counts above the caps. NOT TESTED on a real Windows host by the author: read the dry run.

.EXAMPLE
  .\New-LogUnifyDemoActivity.ps1                                  # dry run: prints the plan
  .\New-LogUnifyDemoActivity.ps1 -Apply                           # 5 failed logons + 5 harmless processes
  .\New-LogUnifyDemoActivity.ps1 -Apply -FailedLogons 8 -BenignProcesses 3 -EncodedPowerShell
#>
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [ValidateRange(0, 25)][int]$FailedLogons = 5,
    [ValidateRange(0, 25)][int]$BenignProcesses = 5,
    [switch]$EncodedPowerShell,
    [ValidateRange(1, 30)][int]$DelaySeconds = 2,
    [string]$ManifestPath = (Join-Path $env:ProgramData 'LogUnify\demo-activity-manifest.json'),
    [switch]$Apply
)
$ErrorActionPreference = 'Stop'

# --- guard rails -------------------------------------------------------------------------------------------------------
$role = (Get-CimInstance Win32_ComputerSystem).DomainRole          # 4 / 5 = domain controller
if ($role -ge 4) { throw "This is a domain controller: failed-logon noise here looks like an attack. Run it on a member server or a lab VM." }
if ($FailedLogons -eq 0 -and $BenignProcesses -eq 0 -and -not $EncodedPowerShell) { throw "Nothing to do: all counts are zero." }
if ($Apply -and (Test-Path $ManifestPath)) {
    $age = (Get-Date) - (Get-Item $ManifestPath).LastWriteTime
    if ($age.TotalMinutes -lt 10) { throw "A run finished $([int]$age.TotalMinutes) minute(s) ago ($ManifestPath). Wait 10 minutes: this tool must not be looped to flood the source." }
}

$suffix = -join ((48..57) + (97..122) | Get-Random -Count 6 | ForEach-Object { [char]$_ })
$user = "logunify_demo_$suffix"
if (Get-LocalUser -Name $user -ErrorAction SilentlyContinue) { throw "User '$user' unexpectedly exists; run again." }

$plan = @(
    "$FailedLogons failed network logon(s) for the non-existent user '$user' (expect event 4625, logon type 3)",
    "$BenignProcesses harmless process start(s): hostname, whoami, cmd echo 'logunify-demo' (expect event 4688 with the marker in the command line)"
)
if ($EncodedPowerShell) { $plan += "1 harmless -EncodedCommand PowerShell that only prints a sentence (expect 4688; may be flagged by AV/EDR)" }
Write-Host "Plan on $env:COMPUTERNAME:" -ForegroundColor Cyan
$plan | ForEach-Object { Write-Host "  - $_" }
Write-Host "Markers to search for in LogUnify: user.name:logunify_demo*   and the text 'logunify-demo'"
if (-not $Apply) { Write-Host "`nDRY RUN: nothing was done. Re-run with -Apply (tell your security team first)." -ForegroundColor Yellow; return }

# --- do it -------------------------------------------------------------------------------------------------------------
$started = (Get-Date).ToUniversalTime()
$done = [ordered]@{ failed_logons = 0; processes = @(); encoded_powershell = $false }

for ($i = 1; $i -le $FailedLogons; $i++) {
    $pw = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 14 | ForEach-Object { [char]$_ })
    & cmd.exe /c "net use \\127.0.0.1\IPC`$ /user:$user $pw >nul 2>&1" | Out-Null      # fails (error 1326): that failure IS the event
    $done.failed_logons++
    Write-Host ("  failed logon {0}/{1} for {2}" -f $i, $FailedLogons, $user)
    Start-Sleep -Seconds $DelaySeconds
}

$benign = @(
    @{ f = 'hostname.exe'; a = @() },
    @{ f = 'whoami.exe'; a = @() },
    @{ f = 'cmd.exe'; a = @('/c', 'echo', 'logunify-demo') }
)
for ($i = 0; $i -lt $BenignProcesses; $i++) {
    $p = $benign[$i % $benign.Count]
    $argList = $p.a
    if ($argList.Count) { Start-Process -FilePath $p.f -ArgumentList $argList -WindowStyle Hidden -Wait } else { Start-Process -FilePath $p.f -WindowStyle Hidden -Wait -RedirectStandardOutput "$env:TEMP\logunify-demo.out" }
    $done.processes += $p.f
    Write-Host ("  process {0}/{1}: {2}" -f ($i + 1), $BenignProcesses, $p.f)
    Start-Sleep -Seconds $DelaySeconds
}
Remove-Item "$env:TEMP\logunify-demo.out" -ErrorAction SilentlyContinue

if ($EncodedPowerShell) {
    $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Write-Output 'logunify-demo: benign encoded command'"))
    Start-Process -FilePath powershell.exe -ArgumentList '-NoProfile', '-NonInteractive', '-EncodedCommand', $enc -WindowStyle Hidden -Wait
    $done.encoded_powershell = $true
    Write-Host "  encoded PowerShell (benign) done"
}

$ended = (Get-Date).ToUniversalTime()
$manifest = [ordered]@{
    tool = 'New-LogUnifyDemoActivity.ps1'; purpose = 'controlled test activity: NOT production traffic, NOT a baseline'
    host = $env:COMPUTERNAME; run_by = "$env:USERDOMAIN\$env:USERNAME"; started_utc = $started.ToString('o'); ended_utc = $ended.ToString('o')
    fake_user = $user; counts = $done
}
New-Item -ItemType Directory -Force -Path (Split-Path $ManifestPath) | Out-Null
$manifest | ConvertTo-Json -Depth 5 | Set-Content -Path $ManifestPath -Encoding UTF8

Write-Host "`nDone. Manifest: $ManifestPath" -ForegroundColor Green
Write-Host ("Find the events in LogUnify (Search, Parser = windows_security): from {0:u} to {1:u}, user.name:logunify_demo*" -f $started, $ended)
Write-Host "In the report: call them 'controlled test activity', cite the manifest, and keep them out of calibration."
