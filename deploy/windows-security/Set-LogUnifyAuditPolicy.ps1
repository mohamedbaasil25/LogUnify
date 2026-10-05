<#
.SYNOPSIS
  Turns on the Windows audit settings LogUnify's windows_security parser and alert rules rely on. DRY RUN by default.

.DESCRIPTION
  Shows what it would change; nothing is modified unless you pass -Apply. Run elevated, on the host whose log you are onboarding.
  Settings (see logunify-backend/docs/WINDOWS_SECURITY.md):
    * Advanced Audit Policy subcategories: Logon, Logoff, Special Logon, Account Lockout, User Account Management, Security Group Management,
      Process Creation, Audit Policy Change, Security System Extension (success + failure).
    * "Force audit policy subcategory settings" (otherwise legacy basic audit policy can override the subcategories).
    * Command line in process-creation events (4688).
    * Security log size, so a busy hour does not overwrite events before NXLog reads them.

  DOMAIN-JOINED HOSTS: a Group Policy that sets audit policy overrides this local change at the next refresh. Put the same settings in a GPO
  for a real rollout; this script is for a single host / a pilot.
  Subcategory names are the ENGLISH names: on a localized Windows, auditpol will report an error for each name (the script says so; use `auditpol /list /subcategory:*`).

  NOT TESTED ON A REAL WINDOWS HOST by the author of this repository: run it with no switch first and read the output.

.EXAMPLE
  .\Set-LogUnifyAuditPolicy.ps1            # dry run: prints current state and the commands it would run
  .\Set-LogUnifyAuditPolicy.ps1 -Apply     # applies
#>
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [switch]$Apply,
    [int]$SecurityLogMaxMB = 512
)
$ErrorActionPreference = 'Continue'
$failed = 0

$subcategories = 'Logon', 'Logoff', 'Special Logon', 'Account Lockout', 'User Account Management', 'Security Group Management',
                 'Process Creation', 'Audit Policy Change', 'Security System Extension'

Write-Host "== Audit policy subcategories ==" -ForegroundColor Cyan
foreach ($s in $subcategories) {
    $cur = (auditpol /get /subcategory:"$s" 2>&1 | Select-String -Pattern 'Success|Failure|No Auditing|Erfolg|Fehler' | ForEach-Object { $_.Line.Trim() }) -join ' | '
    Write-Host ("{0,-28} now: {1}" -f $s, $(if ($cur) { $cur } else { '(could not read)' }))
    if ($Apply) {
        $out = auditpol /set /subcategory:"$s" /success:enable /failure:enable 2>&1
        if ($LASTEXITCODE -ne 0) { Write-Warning "auditpol failed for '$s': $out"; $failed++ } else { Write-Host "    set: success+failure" -ForegroundColor Green }
    } else {
        Write-Host "    would run: auditpol /set /subcategory:`"$s`" /success:enable /failure:enable"
    }
}

Write-Host "`n== Registry settings ==" -ForegroundColor Cyan
$settings = @(
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'SCENoApplyLegacyAuditPolicy'; Value = 1; Why = 'subcategory settings win over legacy audit policy' },
    @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'; Name = 'ProcessCreationIncludeCmdLine_Enabled'; Value = 1; Why = 'command line in 4688 (privacy: command lines can contain secrets)' }
)
foreach ($r in $settings) {
    $cur = (Get-ItemProperty -Path $r.Path -Name $r.Name -ErrorAction SilentlyContinue).($r.Name)
    Write-Host ("{0}\{1}  now: {2}  want: {3}  ({4})" -f $r.Path, $r.Name, $(if ($null -eq $cur) { '(not set)' } else { $cur }), $r.Value, $r.Why)
    if ($Apply -and $cur -ne $r.Value) {
        try {
            if (-not (Test-Path $r.Path)) { New-Item -Path $r.Path -Force | Out-Null }
            New-ItemProperty -Path $r.Path -Name $r.Name -Value $r.Value -PropertyType DWord -Force | Out-Null
            Write-Host "    set" -ForegroundColor Green
        } catch { Write-Warning "could not set $($r.Name): $_"; $failed++ }
    }
}

Write-Host "`n== Security event log size ==" -ForegroundColor Cyan
$bytes = [int64]$SecurityLogMaxMB * 1MB
$cfg = wevtutil gl Security 2>&1 | Select-String -Pattern 'maxSize' | ForEach-Object { $_.Line.Trim() }
Write-Host "now: $cfg   want: maxSize: $bytes"
if ($Apply) {
    wevtutil sl Security /ms:$bytes 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { Write-Warning "wevtutil could not set the Security log size"; $failed++ } else { Write-Host "set" -ForegroundColor Green }
}

Write-Host ""
if (-not $Apply) { Write-Host "DRY RUN: nothing was changed. Re-run with -Apply to apply." -ForegroundColor Yellow }
elseif ($failed) { Write-Warning "$failed step(s) failed (see above)."; exit 1 }
else { Write-Host "Done. Generate a test event (e.g. lock/unlock the screen) and look for 4624/4634 in Event Viewer > Security." -ForegroundColor Green }
