#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Tactical RMM - Update all agents to latest version.
    Create as a script in Tactical RMM, assign to all agents, run.
    Timeout: 600 seconds.
#>

$ErrorActionPreference = "Stop"
$TempDir = "$env:TEMP\pcplus-update"
$GitHubRepo = "anirudhatalmale6-alt/pcplus-support-tray"

Write-Host "PC Plus Endpoint - Agent Update"
Write-Host "================================"

# Download the update script
New-Item -Path $TempDir -ItemType Directory -Force | Out-Null
$scriptUrl = "https://raw.githubusercontent.com/$GitHubRepo/main/deploy/Update-Agent.ps1"
Write-Host "Downloading update script..."
Invoke-WebRequest -Uri $scriptUrl -OutFile "$TempDir\Update-Agent.ps1" -UseBasicParsing

# Run the update
Write-Host "Running update..."
& "$TempDir\Update-Agent.ps1"

# Cleanup
Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "Update complete! Agent will report to dashboard within 30 seconds."
