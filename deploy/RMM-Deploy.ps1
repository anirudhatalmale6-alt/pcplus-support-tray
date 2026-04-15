#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Quick deploy script for Tactical RMM.
    Copy this into a Tactical RMM script and run on target endpoints.
    Customize the parameters below for your deployment.
#>

# === CUSTOMIZE THESE FOR YOUR DEPLOYMENT ===
$DashboardUrl    = "https://dashboard.pcpluscomputing.com"
$CustomerName    = "{{client.name}}"     # Tactical RMM variable
$CustomerId      = "{{client.id}}"       # Tactical RMM variable
$PolicyProfile   = "default"             # default, high-security, home-user
$LicenseKey      = ""                    # Leave empty for Free tier
$GitHubRepo      = "anirudhatalmale6-alt/pcplus-support-tray"
# === END CUSTOMIZATION ===

$ErrorActionPreference = "Stop"
$TempDir = "$env:TEMP\pcplus-install"

Write-Host "PC Plus Endpoint Protection - RMM Deploy"
Write-Host "========================================="

# Download the installer script
New-Item -Path $TempDir -ItemType Directory -Force | Out-Null
$installerUrl = "https://raw.githubusercontent.com/$GitHubRepo/main/deploy/Install-PCPlusEndpoint.ps1"
Write-Host "Downloading installer from $installerUrl..."
Invoke-WebRequest -Uri $installerUrl -OutFile "$TempDir\Install-PCPlusEndpoint.ps1" -UseBasicParsing

# Run the installer
Write-Host "Running installer..."
& "$TempDir\Install-PCPlusEndpoint.ps1" `
    -DashboardUrl $DashboardUrl `
    -CustomerName $CustomerName `
    -CustomerId $CustomerId `
    -PolicyProfile $PolicyProfile `
    -LicenseKey $LicenseKey `
    -GitHubRepo $GitHubRepo

# Cleanup
Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "Deploy complete! Device will appear in dashboard within 30 seconds."
