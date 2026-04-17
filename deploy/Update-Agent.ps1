#Requires -RunAsAdministrator
<#
.SYNOPSIS
    PC Plus Endpoint Protection - Quick Update Script
    Updates existing agents to the latest version without changing config.
    Push via Tactical RMM or run manually on endpoints.

.DESCRIPTION
    Downloads latest release from GitHub, stops service/tray, swaps binaries,
    restarts everything. Config and logs are preserved.

.PARAMETER GitHubRepo
    GitHub repository for downloading releases.

.PARAMETER TargetVersion
    Specific version tag to install (e.g. "v4.4.0"). Leave empty for latest.

.EXAMPLE
    # Update to latest via Tactical RMM:
    .\Update-Agent.ps1

    # Update to specific version:
    .\Update-Agent.ps1 -TargetVersion "v4.4.0"
#>

param(
    [string]$GitHubRepo = "anirudhatalmale6-alt/pcplus-support-tray",
    [string]$TargetVersion = ""
)

$ErrorActionPreference = "Stop"
$ServiceName = "PCPlusEndpoint"
$InstallDir = "$env:ProgramFiles\PC Plus\Endpoint Protection"
$ConfigDir = "$env:ProgramData\PCPlusEndpoint"
$LogFile = "$ConfigDir\Logs\update.log"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$timestamp] [$Level] $Message"
    Write-Host $line
    if (Test-Path (Split-Path $LogFile -ErrorAction SilentlyContinue)) {
        Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
    }
}

# Check if agent is installed
if (-not (Test-Path "$InstallDir\Service\PCPlusService.exe")) {
    Write-Host "ERROR: PC Plus Endpoint not installed. Use Install-PCPlusEndpoint.ps1 for first install."
    exit 1
}

# Get current version
$currentVersion = "unknown"
try {
    $svcExe = Get-Item "$InstallDir\Service\PCPlusService.exe"
    $currentVersion = $svcExe.VersionInfo.FileVersion
} catch {}
Write-Log "Current version: $currentVersion"

# Get target release
if ($TargetVersion) {
    $releaseUrl = "https://api.github.com/repos/$GitHubRepo/releases/tags/$TargetVersion"
} else {
    $releaseUrl = "https://api.github.com/repos/$GitHubRepo/releases/latest"
}

Write-Log "Fetching release info..."
try {
    $release = Invoke-RestMethod -Uri $releaseUrl -UseBasicParsing
} catch {
    Write-Log "Failed to fetch release: $_" "ERROR"
    exit 1
}

$newVersion = $release.tag_name
Write-Log "Target version: $newVersion"

# Find installer asset
$installerAsset = $release.assets | Where-Object { $_.name -like "*Installer*" -or $_.name -like "*installer*" } | Select-Object -First 1
if (-not $installerAsset) {
    Write-Log "No installer asset found in release $newVersion" "ERROR"
    exit 1
}

# Download
$zipPath = "$env:TEMP\pcplus-update.zip"
$extractPath = "$env:TEMP\pcplus-update-extract"
Write-Log "Downloading $($installerAsset.name)..."
Invoke-WebRequest -Uri $installerAsset.browser_download_url -OutFile $zipPath -UseBasicParsing

if (Test-Path $extractPath) { Remove-Item $extractPath -Recurse -Force }
Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force
Remove-Item $zipPath -Force

# Stop service
Write-Log "Stopping service..."
Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 3

# Stop tray app
Write-Log "Stopping tray app..."
Get-Process -Name "PCPlusTray" -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 1

# Swap service binaries
$svcSource = Get-ChildItem -Path $extractPath -Filter "PCPlusService.exe" -Recurse | Select-Object -First 1
if ($svcSource) {
    Write-Log "Updating service binaries..."
    Copy-Item -Path "$($svcSource.DirectoryName)\*" -Destination "$InstallDir\Service" -Recurse -Force
}

# Swap tray binaries
$traySource = Get-ChildItem -Path $extractPath -Filter "PCPlusTray.exe" -Recurse | Select-Object -First 1
if ($traySource) {
    Write-Log "Updating tray binaries..."
    Copy-Item -Path "$($traySource.DirectoryName)\*" -Destination "$InstallDir\Tray" -Recurse -Force
}

# Cleanup
Remove-Item $extractPath -Recurse -Force -ErrorAction SilentlyContinue

# Start service
Write-Log "Starting service..."
Start-Service -Name $ServiceName
Write-Log "Service started."

# Start tray app for current user
$trayExe = "$InstallDir\Tray\PCPlusTray.exe"
if (Test-Path $trayExe) {
    Start-Process -FilePath $trayExe -WindowStyle Hidden
    Write-Log "Tray app started."
}

# Update version in uninstall registry
$uninstallKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\PCPlusEndpoint"
if (Test-Path $uninstallKey) {
    Set-ItemProperty -Path $uninstallKey -Name "DisplayVersion" -Value $newVersion
}

Write-Log "Update complete! $currentVersion -> $newVersion"
Write-Log "Security audit data will appear in dashboard within 30 seconds."
