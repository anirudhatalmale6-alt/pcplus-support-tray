<#
.SYNOPSIS
    RMM Deployment - Install PC Plus Network Security Collector
    Push via Tactical RMM. Sets up scheduled task that collects security data
    every 30 minutes for 14 days, then generate report.
.NOTES
    Run as: Administrator | Timeout: 600 seconds
.PARAMETER DisableNetworkScan
    Set to $true to disable network scanning (device discovery, service detection)
    Useful if you don't want the agent scanning the network
.PARAMETER Days
    Number of days to collect data (default: 14)
.PARAMETER Interval
    Collection interval in minutes (default: 30)
#>

param(
    [switch]$DisableNetworkScan,
    [int]$Days = 14,
    [int]$Interval = 30
)

$BaseDir = "$env:ProgramData\PCPlusEndpoint\NetworkSecurity"
$RepoBase = "https://raw.githubusercontent.com/anirudhatalmale6-alt/pcplus-support-tray/main/scripts"

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
New-Item -Path $BaseDir -ItemType Directory -Force | Out-Null

Write-Host "=== PC Plus Network Security Collector Setup ===" -ForegroundColor Cyan

# Download scripts
Write-Host "Downloading collector..." -ForegroundColor Yellow
try {
    Invoke-WebRequest -Uri "$RepoBase/PCPlus-NetworkCollector.ps1" -OutFile "$BaseDir\PCPlus-NetworkCollector.ps1" -UseBasicParsing
    Invoke-WebRequest -Uri "$RepoBase/PCPlus-NetworkSecurityScan.ps1" -OutFile "$BaseDir\PCPlus-NetworkSecurityScan.ps1" -UseBasicParsing
} catch {
    Write-Host "Download failed: $_" -ForegroundColor Red
    exit 1
}

# Install
Write-Host "Installing collector (${Days}-day assessment, every ${Interval} min)..." -ForegroundColor Yellow
$installArgs = "-Mode install -CollectionDays $Days -IntervalMinutes $Interval"
if ($DisableNetworkScan) { $installArgs += " -DisableNetworkScan" }

& powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$BaseDir\PCPlus-NetworkCollector.ps1" $installArgs.Split(' ')

Write-Host "`n=== DEPLOYMENT COMPLETE ===" -ForegroundColor Green
Write-Host "Collector will run every $Interval minutes for $Days days" -ForegroundColor Cyan
Write-Host "Network scanning: $(if(-not $DisableNetworkScan){'ENABLED'}else{'DISABLED - use -DisableNetworkScan:`$false to enable'})" -ForegroundColor White
Write-Host ""
Write-Host "To generate report at any time:" -ForegroundColor Yellow
Write-Host "  powershell -File `"$BaseDir\PCPlus-NetworkCollector.ps1`" -Mode report" -ForegroundColor White
Write-Host ""
Write-Host "To check status:" -ForegroundColor Yellow
Write-Host "  powershell -File `"$BaseDir\PCPlus-NetworkCollector.ps1`" -Mode status" -ForegroundColor White
Write-Host ""
Write-Host "To uninstall:" -ForegroundColor Yellow
Write-Host "  powershell -File `"$BaseDir\PCPlus-NetworkCollector.ps1`" -Mode uninstall" -ForegroundColor White
