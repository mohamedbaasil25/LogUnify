<#
.SYNOPSIS
  Renders nxlog.conf.template for this host and (with -Apply) installs it as the NXLog configuration. DRY RUN by default.

.EXAMPLE
  .\Install-LogUnifyForwarder.ps1 -LogUnifyHost logunify.corp.example.com -Port 5514                       # plain TCP, private network only; dry run
  .\Install-LogUnifyForwarder.ps1 -LogUnifyHost logunify.corp.example.com -Port 6514 -Tls -CaFile C:\certs\ca.pem -CertFile C:\certs\host.pem -KeyFile C:\certs\host.key -Apply

.NOTES
  NXLog Community / Enterprise must already be installed (https://nxlog.co/downloads). The existing nxlog.conf is backed up first. Checks the rendered
  configuration with `nxlog.exe -v` before restarting the service. NOT tested on a live NXLog by the author: read the dry-run output.
#>
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$LogUnifyHost,
    [int]$Port = 5514,
    [switch]$Tls,
    [string]$CaFile,
    [string]$CertFile,
    [string]$KeyFile,
    [string]$NxlogDir = 'C:\Program Files\nxlog',
    [switch]$Apply
)
$ErrorActionPreference = 'Stop'
$template = Join-Path $PSScriptRoot 'nxlog.conf.template'
$conf = Join-Path $NxlogDir 'conf\nxlog.conf'
if (-not (Test-Path $template)) { throw "template not found next to this script: $template" }
if ($LogUnifyHost -notmatch '^[A-Za-z0-9._-]+$') { throw "LogUnifyHost must be a host name or IP address" }

if ($Tls) {
    foreach ($f in @($CaFile, $CertFile, $KeyFile)) { if (-not $f -or -not (Test-Path $f)) { throw "-Tls needs existing -CaFile, -CertFile and -KeyFile (mutual TLS); missing: '$f'" } }
    $out = @"
    Module      om_ssl
    Host        $LogUnifyHost
    Port        $Port
    CAFile      $CaFile
    CertFile    $CertFile
    CertKeyFile $KeyFile
    AllowUntrusted FALSE
"@
} else {
    Write-Warning "Plain TCP: events (user names, IPs, command lines) cross the network unencrypted. Use only on a private segment, or -Tls."
    $out = @"
    Module      om_tcp
    Host        $LogUnifyHost
    Port        $Port
"@
}
$rendered = (Get-Content $template -Raw).Replace('@@OUTPUT_MODULE@@', $out)

Write-Host "Target: $conf`nOutput: $(if ($Tls) { 'TLS (mutual)' } else { 'plain TCP' }) -> ${LogUnifyHost}:$Port`n"
Write-Host "---- rendered output section ----`n$out`n---------------------------------"
if (-not $Apply) { Write-Host "DRY RUN: nothing was written. Re-run with -Apply." -ForegroundColor Yellow; return }

if (-not (Test-Path (Join-Path $NxlogDir 'nxlog.exe'))) { throw "nxlog.exe not found in $NxlogDir (install NXLog first, or pass -NxlogDir)" }
if (Test-Path $conf) { Copy-Item $conf "$conf.bak-$(Get-Date -Format yyyyMMddHHmmss)" }
Set-Content -Path $conf -Value $rendered -Encoding ASCII
& (Join-Path $NxlogDir 'nxlog.exe') -v -c $conf
if ($LASTEXITCODE -ne 0) { throw "nxlog.exe rejected the configuration; the previous file is saved as $conf.bak-*" }
Restart-Service nxlog
Start-Sleep -Seconds 3
Write-Host ("nxlog service: " + (Get-Service nxlog).Status) -ForegroundColor Green
Write-Host "Check C:\Program Files\nxlog\data\nxlog.log for connection errors, then run scripts/verify_windows_onboarding.py on the LogUnify side."
