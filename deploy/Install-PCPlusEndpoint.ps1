#Requires -RunAsAdministrator
<#
.SYNOPSIS
    PC Plus Endpoint Protection - Install/Update Script
    Push via Tactical RMM, PDQ Deploy, GPO, or run manually.

.DESCRIPTION
    Downloads and installs both the Windows Service and Tray App.
    Configures the service, sets up auto-start, and optionally
    configures the dashboard phone-home URL.

.PARAMETER DashboardUrl
    URL of the central dashboard (e.g. https://dashboard.pcpluscomputing.com)
    If set, the endpoint will phone home every 30 seconds.

.PARAMETER CustomerId
    Customer identifier for grouping in the dashboard.

.PARAMETER CustomerName
    Customer display name for the dashboard.

.PARAMETER PolicyProfile
    Policy profile to apply: default, high-security, home-user

.PARAMETER LicenseKey
    License key for Premium/Standard features.

.PARAMETER GitHubRepo
    GitHub repository for downloading releases.

.PARAMETER Uninstall
    Remove PC Plus Endpoint Protection completely.

.EXAMPLE
    # Push via Tactical RMM:
    .\Install-PCPlusEndpoint.ps1 -DashboardUrl "https://dashboard.pcpluscomputing.com" -CustomerName "Acme Corp"

    # Silent install with license:
    .\Install-PCPlusEndpoint.ps1 -DashboardUrl "https://dashboard.pcpluscomputing.com" -LicenseKey "XXXX-XXXX" -PolicyProfile "high-security"
#>

param(
    [string]$DashboardUrl = "",
    [string]$CustomerId = "",
    [string]$CustomerName = "",
    [string]$PolicyProfile = "default",
    [string]$LicenseKey = "",
    [string]$GitHubRepo = "anirudhatalmale6-alt/pcplus-support-tray",
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"
$ServiceName = "PCPlusEndpoint"
$TrayAppName = "PCPlusTray"
$InstallDir = "$env:ProgramFiles\PC Plus\Endpoint Protection"
$ConfigDir = "$env:ProgramData\PCPlusEndpoint"
$LogFile = "$ConfigDir\Logs\install.log"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$timestamp] [$Level] $Message"
    Write-Host $line
    if (Test-Path (Split-Path $LogFile)) {
        Add-Content -Path $LogFile -Value $line
    }
}

function Get-LatestRelease {
    Write-Log "Checking for latest release from GitHub..."
    try {
        $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$GitHubRepo/releases/latest" -UseBasicParsing
        return $release
    }
    catch {
        # If no releases yet, use the main branch build artifacts
        Write-Log "No releases found. Will build from source or use pre-built binaries." "WARN"
        return $null
    }
}

function Install-Service {
    Write-Log "Installing PC Plus Endpoint Protection..."

    # Create directories
    New-Item -Path $InstallDir -ItemType Directory -Force | Out-Null
    New-Item -Path "$InstallDir\Service" -ItemType Directory -Force | Out-Null
    New-Item -Path "$InstallDir\Tray" -ItemType Directory -Force | Out-Null
    New-Item -Path $ConfigDir -ItemType Directory -Force | Out-Null
    New-Item -Path "$ConfigDir\Logs" -ItemType Directory -Force | Out-Null
    New-Item -Path "$ConfigDir\Audits" -ItemType Directory -Force | Out-Null

    # Stop existing service if running
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc) {
        Write-Log "Stopping existing service..."
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    }

    # Stop existing tray app
    Get-Process -Name "PCPlusTray" -ErrorAction SilentlyContinue | Stop-Process -Force

    # Download or copy binaries
    $release = Get-LatestRelease
    if ($release) {
        # Download from GitHub release
        $serviceAsset = $release.assets | Where-Object { $_.name -like "*Service*" -or $_.name -like "*service*" } | Select-Object -First 1
        $trayAsset = $release.assets | Where-Object { $_.name -like "*Tray*" -or $_.name -like "*tray*" } | Select-Object -First 1

        if ($serviceAsset) {
            Write-Log "Downloading service: $($serviceAsset.name)..."
            $servicePath = "$env:TEMP\pcplus-service.zip"
            Invoke-WebRequest -Uri $serviceAsset.browser_download_url -OutFile $servicePath -UseBasicParsing
            Expand-Archive -Path $servicePath -DestinationPath "$InstallDir\Service" -Force
            Remove-Item $servicePath -Force
        }

        if ($trayAsset) {
            Write-Log "Downloading tray app: $($trayAsset.name)..."
            $trayPath = "$env:TEMP\pcplus-tray.zip"
            Invoke-WebRequest -Uri $trayAsset.browser_download_url -OutFile $trayPath -UseBasicParsing
            Expand-Archive -Path $trayPath -DestinationPath "$InstallDir\Tray" -Force
            Remove-Item $trayPath -Force
        }
    }
    else {
        Write-Log "No release assets found. Checking for local binaries..."
        # Check if binaries exist in the script directory
        $scriptDir = Split-Path -Parent $MyInvocation.ScriptName
        if (Test-Path "$scriptDir\Service\PCPlusService.exe") {
            Write-Log "Copying local service binaries..."
            Copy-Item -Path "$scriptDir\Service\*" -Destination "$InstallDir\Service" -Recurse -Force
        }
        if (Test-Path "$scriptDir\Tray\PCPlusTray.exe") {
            Write-Log "Copying local tray binaries..."
            Copy-Item -Path "$scriptDir\Tray\*" -Destination "$InstallDir\Tray" -Recurse -Force
        }
    }

    # Write config file
    Write-Config

    # Install Windows Service
    $serviceExe = "$InstallDir\Service\PCPlusService.exe"
    if (Test-Path $serviceExe) {
        # Remove old service registration if exists
        if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
            Write-Log "Removing old service registration..."
            sc.exe delete $ServiceName | Out-Null
            Start-Sleep -Seconds 1
        }

        Write-Log "Registering Windows Service..."
        New-Service -Name $ServiceName `
            -BinaryPathName $serviceExe `
            -DisplayName "PC Plus Endpoint Protection" `
            -Description "PC Plus Endpoint Protection - Background security monitoring, ransomware defense, and system health." `
            -StartupType Automatic `
            -ErrorAction Stop | Out-Null

        # Set service to auto-restart on failure
        sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null

        # Start the service
        Write-Log "Starting service..."
        Start-Service -Name $ServiceName
        Write-Log "Service started successfully."
    }
    else {
        Write-Log "Service binary not found at $serviceExe. Build the solution first." "WARN"
    }

    # Set up Tray App auto-start for all users
    $trayExe = "$InstallDir\Tray\PCPlusTray.exe"
    if (Test-Path $trayExe) {
        Write-Log "Configuring tray app auto-start..."

        # Registry key for auto-start (all users)
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        Set-ItemProperty -Path $regPath -Name "PCPlusEndpoint" -Value "`"$trayExe`""

        # Start the tray app for the current user
        Start-Process -FilePath $trayExe -WindowStyle Hidden
        Write-Log "Tray app configured for auto-start."
    }

    # Create uninstall registry entry
    $uninstallKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\PCPlusEndpoint"
    New-Item -Path $uninstallKey -Force | Out-Null
    Set-ItemProperty -Path $uninstallKey -Name "DisplayName" -Value "PC Plus Endpoint Protection"
    Set-ItemProperty -Path $uninstallKey -Name "DisplayVersion" -Value "4.1.0"
    Set-ItemProperty -Path $uninstallKey -Name "Publisher" -Value "PC Plus Computing"
    Set-ItemProperty -Path $uninstallKey -Name "InstallLocation" -Value $InstallDir
    Set-ItemProperty -Path $uninstallKey -Name "UninstallString" -Value "powershell.exe -ExecutionPolicy Bypass -File `"$InstallDir\Uninstall.ps1`""

    # Copy uninstall script
    $uninstallScript = @'
#Requires -RunAsAdministrator
$ServiceName = "PCPlusEndpoint"
Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
sc.exe delete $ServiceName
Get-Process -Name "PCPlusTray" -ErrorAction SilentlyContinue | Stop-Process -Force
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "PCPlusEndpoint" -ErrorAction SilentlyContinue
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\PCPlusEndpoint" -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "$env:ProgramFiles\PC Plus\Endpoint Protection" -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "PC Plus Endpoint Protection has been uninstalled."
'@
    Set-Content -Path "$InstallDir\Uninstall.ps1" -Value $uninstallScript

    Write-Log "Installation complete!"
    Write-Log "Install dir: $InstallDir"
    Write-Log "Config dir: $ConfigDir"
    if ($DashboardUrl) {
        Write-Log "Dashboard: $DashboardUrl"
    }
}

function Write-Config {
    $configFile = "$ConfigDir\config.json"

    # Load existing config if present
    $config = @{}
    if (Test-Path $configFile) {
        try {
            $existing = Get-Content $configFile -Raw | ConvertFrom-Json
            $existing.PSObject.Properties | ForEach-Object {
                $config[$_.Name] = $_.Value
            }
        }
        catch { }
    }

    # Apply install parameters (don't overwrite existing values unless explicitly set)
    if ($DashboardUrl) { $config["dashboardApiUrl"] = $DashboardUrl }
    if ($CustomerId) { $config["customerId"] = $CustomerId }
    if ($CustomerName) { $config["companyName"] = $CustomerName }
    if ($PolicyProfile) { $config["policyProfile"] = $PolicyProfile }
    if ($LicenseKey) { $config["licenseKey"] = $LicenseKey }

    # Set defaults if not present
    if (-not $config.ContainsKey("ransomwareProtectionEnabled")) { $config["ransomwareProtectionEnabled"] = "true" }
    if (-not $config.ContainsKey("autoContainmentEnabled")) { $config["autoContainmentEnabled"] = "true" }
    if (-not $config.ContainsKey("showBalloonAlerts")) { $config["showBalloonAlerts"] = "true" }
    if (-not $config.ContainsKey("logAlerts")) { $config["logAlerts"] = "true" }

    # Save
    $config | ConvertTo-Json -Depth 10 | Set-Content -Path $configFile -Encoding UTF8
    Write-Log "Config written to $configFile"
}

function Uninstall-Service {
    Write-Log "Uninstalling PC Plus Endpoint Protection..."

    # Stop and remove service
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    sc.exe delete $ServiceName 2>$null

    # Stop tray app
    Get-Process -Name "PCPlusTray" -ErrorAction SilentlyContinue | Stop-Process -Force

    # Remove auto-start
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "PCPlusEndpoint" -ErrorAction SilentlyContinue

    # Remove uninstall entry
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\PCPlusEndpoint" -Recurse -ErrorAction SilentlyContinue

    # Remove files (keep config/logs for potential reinstall)
    Remove-Item -Path $InstallDir -Recurse -Force -ErrorAction SilentlyContinue

    Write-Log "Uninstall complete. Config and logs preserved at $ConfigDir"
    Write-Log "To remove config/logs too: Remove-Item '$ConfigDir' -Recurse -Force"
}

# --- Main ---
if ($Uninstall) {
    Uninstall-Service
}
else {
    # Ensure log directory exists
    New-Item -Path "$ConfigDir\Logs" -ItemType Directory -Force | Out-Null
    Install-Service
}
