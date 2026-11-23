<#
.SYNOPSIS
    NetShaper v6.3 — Windows 11 Network Hygiene Diagnostic & Opt-In Remediation Helper.
.DESCRIPTION
    Strictly READ-ONLY by default. Audits Windows 11 TCP stack parameters (RSS, Auto-Tuning,
    ECN, HyStart, Path MTU discovery) and Windows Defender Firewall outbound rules affecting
    gh.exe, ssh.exe, xray.exe, and NetShaper.exe.
    Pass -ApplyRecommended from an elevated PowerShell prompt ONLY if you explicitly consent
    to applying recommended non-destructive TCP stack settings.
#>
[CmdletBinding()]
param(
    [switch]$ApplyRecommended
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

Write-Host "=== NetShaper v6.3 Windows 11 Network Hygiene Diagnostic ===" -ForegroundColor Cyan
Write-Host "Mode: $(if ($ApplyRecommended) { 'OPT-IN REMEDIATION (-ApplyRecommended)' } else { 'READ-ONLY AUDIT (safe default)' })"
Write-Host ""

Write-Host "[1/4] TCP Global Parameters (netsh int tcp show global):" -ForegroundColor Yellow
netsh int tcp show global

Write-Host "`n[2/4] Supplemental Congestion Provider (netsh int tcp show supplemental):" -ForegroundColor Yellow
netsh int tcp show supplemental

Write-Host "`n[3/4] Defender Firewall Profiles (netsh advfirewall show allprofiles state):" -ForegroundColor Yellow
netsh advfirewall show allprofiles state

Write-Host "`n[4/4] Checking Outbound Block Rules for gh.exe / ssh.exe / xray.exe / NetShaper.exe:" -ForegroundColor Yellow
$rules = netsh advfirewall firewall show rule name=all dir=out
$targets = @("gh.exe", "ssh.exe", "xray.exe", "netshaper.exe")
$blocks = $rules -split "(?=\r?\nRule Name:)" | Where-Object {
    $_ -match "Enabled:\s+Yes" -and $_ -match "Action:\s+Block" -and (
        $targets | Where-Object { $_ -and ($args_item = $_) } | ForEach-Object { $true }
    )
}
$foundBlock = $false
foreach ($chunk in ($rules -split "(?=\r?\nRule Name:)")) {
    if ($chunk -match "Enabled:\s+Yes" -and $chunk -match "Action:\s+Block") {
        foreach ($bin in $targets) {
            if ($chunk.ToLowerInvariant().Contains($bin)) {
                $foundBlock = $true
                Write-Host "  [WARN] Enabled outbound BLOCK rule matched $bin" -ForegroundColor Red
                Write-Host ($chunk.Trim())
                Write-Host ""
            }
        }
    }
}
if (-not $foundBlock) {
    Write-Host "  [OK] No enabled outbound Defender Firewall BLOCK rules found for tunnel binaries." -ForegroundColor Green
}

if ($ApplyRecommended) {
    Write-Host "`nApplying recommended MCI PMTU=576 / cellular TCP stack settings..." -ForegroundColor Cyan
    netsh int tcp set global rss=enabled
    netsh int tcp set global autotuninglevel=normal
    netsh int tcp set global ecncapability=disabled
    netsh int tcp set global hystart=disabled
    Write-Host "Done. Re-run without -ApplyRecommended to verify." -ForegroundColor Green
} else {
    Write-Host "`nNo OS settings were modified. Re-run with -ApplyRecommended as Administrator if needed." -ForegroundColor Gray
}
