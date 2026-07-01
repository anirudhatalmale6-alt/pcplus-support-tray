<#
.SYNOPSIS
    RMM Deployment Script - Downloads and runs PC Plus Network Security Scanner
    Push via Tactical RMM as a script. Runs once, generates report.
.NOTES
    Run as: Administrator
    Timeout: 300 seconds
#>

$ScriptUrl = "https://raw.githubusercontent.com/anirudhatalmale6-alt/pcplus-support-tray/main/scripts/PCPlus-NetworkSecurityScan.ps1"
$OutputDir = "$env:ProgramData\PCPlusEndpoint\NetworkSecurity"
$ScriptPath = "$OutputDir\PCPlus-NetworkSecurityScan.ps1"

New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null

Write-Host "Downloading Network Security Scanner..."
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $ScriptUrl -OutFile $ScriptPath -UseBasicParsing
} catch {
    Write-Host "Download failed: $_" -ForegroundColor Red
    exit 1
}

Write-Host "Running scan (7-day lookback)..."
& $ScriptPath -DaysBack 7

$reportPath = "$OutputDir\report.html"
if (Test-Path $reportPath) {
    Write-Host "SUCCESS - Report generated at: $reportPath" -ForegroundColor Green
    $size = (Get-Item $reportPath).Length / 1KB
    Write-Host "Report size: $([Math]::Round($size, 1)) KB" -ForegroundColor Cyan
} else {
    Write-Host "WARNING: Report file not found" -ForegroundColor Yellow
}
