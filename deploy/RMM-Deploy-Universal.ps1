<#
.SYNOPSIS
    PC Plus Endpoint - Universal Install/Update Script for Tactical RMM
    If not installed: does a fresh install
    If already installed: updates to latest version
    Handles Avast/AV exclusions and common issues

.NOTES
    Tactical RMM Settings:
    - Shell Type: PowerShell
    - Timeout: 600 seconds
    - Run As User: unchecked (runs as SYSTEM)
#>

# === CUSTOMIZE THESE ===
$DashboardUrl    = "https://dashboard.pcpluscomputing.com"
$CustomerName    = "{{site.name}}"       # Tactical RMM variable - auto-fills site/customer name
$CustomerId      = "{{site.id}}"         # Tactical RMM variable
$GitHubRepo      = "anirudhatalmale6-alt/pcplus-support-tray"
# === END CUSTOMIZATION ===

$ErrorActionPreference = "Stop"
$ServiceName = "PCPlusEndpoint"
$InstallDir = "$env:ProgramFiles\PC Plus\Endpoint Protection"
$ConfigDir = "$env:ProgramData\PCPlusEndpoint"
$TempDir = "$env:TEMP\pcplus-deploy"
$LogFile = "$ConfigDir\Logs\deploy.log"

# Create dirs
New-Item -Path $TempDir -ItemType Directory -Force | Out-Null
New-Item -Path "$ConfigDir\Logs" -ItemType Directory -Force | Out-Null

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$timestamp] [$Level] $Message"
    Write-Host $line
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}

# Detect current state
$isInstalled = Test-Path "$InstallDir\Service\PCPlusService.exe"
$currentVersion = "none"
if ($isInstalled) {
    try {
        $svcExe = Get-Item "$InstallDir\Service\PCPlusService.exe"
        $currentVersion = $svcExe.VersionInfo.FileVersion
    } catch { $currentVersion = "unknown" }
}

Write-Log "============================================="
Write-Log "PC Plus Endpoint - Universal Deploy"
Write-Log "============================================="
Write-Log "Machine: $env:COMPUTERNAME"
Write-Log "Installed: $isInstalled (version: $currentVersion)"
Write-Log "Customer: $CustomerName"
Write-Log "Dashboard: $DashboardUrl"

# --- Add AV exclusions (helps with Avast/Defender false positives) ---
Write-Log "Adding Windows Defender exclusions..."
try {
    Add-MpPreference -ExclusionPath $InstallDir -ErrorAction SilentlyContinue
    Add-MpPreference -ExclusionPath $ConfigDir -ErrorAction SilentlyContinue
    Add-MpPreference -ExclusionPath $TempDir -ErrorAction SilentlyContinue
    Add-MpPreference -ExclusionProcess "PCPlusService.exe" -ErrorAction SilentlyContinue
    Add-MpPreference -ExclusionProcess "PCPlusTray.exe" -ErrorAction SilentlyContinue
    Write-Log "Defender exclusions added."
} catch {
    Write-Log "Could not add Defender exclusions (may not be primary AV): $_" "WARN"
}

# --- Get latest release from GitHub ---
Write-Log "Fetching latest release..."
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$GitHubRepo/releases/latest" -UseBasicParsing
    $targetVersion = $release.tag_name
    Write-Log "Latest version: $targetVersion"
} catch {
    Write-Log "Failed to fetch release info: $_" "ERROR"
    exit 1
}

# --- Find installer asset ---
$installerAsset = $release.assets | Where-Object { $_.name -like "*Installer*" } | Select-Object -First 1
if (-not $installerAsset) {
    Write-Log "No installer asset found in release $targetVersion" "ERROR"
    exit 1
}

# --- Download installer package ---
$zipPath = "$TempDir\PCPlusEndpoint-Installer.zip"
$extractPath = "$TempDir\extract"
Write-Log "Downloading $($installerAsset.name) ($([math]::Round($installerAsset.size / 1MB, 1)) MB)..."
try {
    Invoke-WebRequest -Uri $installerAsset.browser_download_url -OutFile $zipPath -UseBasicParsing
    Write-Log "Download complete."
} catch {
    Write-Log "Download failed: $_" "ERROR"
    # Retry with different TLS settings
    Write-Log "Retrying with .NET WebClient..."
    try {
        $wc = New-Object System.Net.WebClient
        $wc.DownloadFile($installerAsset.browser_download_url, $zipPath)
        Write-Log "Download complete (WebClient)."
    } catch {
        Write-Log "Download failed on retry: $_" "ERROR"
        exit 1
    }
}

# --- Extract ---
Write-Log "Extracting..."
if (Test-Path $extractPath) { Remove-Item $extractPath -Recurse -Force }
Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force

# Find binaries
$svcSource = Get-ChildItem -Path $extractPath -Filter "PCPlusService.exe" -Recurse | Select-Object -First 1
$traySource = Get-ChildItem -Path $extractPath -Filter "PCPlusTray.exe" -Recurse | Select-Object -First 1

if (-not $svcSource) {
    Write-Log "PCPlusService.exe not found in download" "ERROR"
    exit 1
}

# --- Stop existing service and tray ---
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    Write-Log "Stopping existing service..."
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    # Force-kill the process if service stop didn't release the file lock
    Get-Process -Name "PCPlusService" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    # Delete service registration so recovery policy can't restart it
    sc.exe delete $ServiceName 2>$null | Out-Null
    Start-Sleep -Seconds 2
}
Get-Process -Name "PCPlusTray" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

# --- Create directories ---
New-Item -Path "$InstallDir\Service" -ItemType Directory -Force | Out-Null
New-Item -Path "$InstallDir\Tray" -ItemType Directory -Force | Out-Null
New-Item -Path "$ConfigDir\Audits" -ItemType Directory -Force | Out-Null

# --- Copy binaries ---
Write-Log "Installing service binaries..."
Copy-Item -Path "$($svcSource.DirectoryName)\*" -Destination "$InstallDir\Service" -Recurse -Force

if ($traySource) {
    Write-Log "Installing tray binaries..."
    Copy-Item -Path "$($traySource.DirectoryName)\*" -Destination "$InstallDir\Tray" -Recurse -Force
}

# --- Write/update config (preserve existing values) ---
$configFile = "$ConfigDir\config.json"
$config = @{}
if (Test-Path $configFile) {
    try {
        $existing = Get-Content $configFile -Raw | ConvertFrom-Json
        $existing.PSObject.Properties | ForEach-Object { $config[$_.Name] = $_.Value }
        Write-Log "Existing config preserved."
    } catch {}
}

# Apply parameters (only if set and not RMM template placeholders)
if ($DashboardUrl -and $DashboardUrl -notlike "*{{*") { $config["dashboardApiUrl"] = $DashboardUrl }
if ($CustomerName -and $CustomerName -notlike "*{{*") { $config["companyName"] = $CustomerName }
if ($CustomerId -and $CustomerId -notlike "*{{*") { $config["customerId"] = $CustomerId }

# Defaults
if (-not $config.ContainsKey("ransomwareProtectionEnabled")) { $config["ransomwareProtectionEnabled"] = "true" }
if (-not $config.ContainsKey("autoContainmentEnabled")) { $config["autoContainmentEnabled"] = "true" }
if (-not $config.ContainsKey("showBalloonAlerts")) { $config["showBalloonAlerts"] = "true" }
if (-not $config.ContainsKey("logAlerts")) { $config["logAlerts"] = "true" }

$config | ConvertTo-Json -Depth 10 | Set-Content -Path $configFile -Encoding UTF8
Write-Log "Config written to $configFile"

# --- Register/restart Windows Service ---
if (-not $isInstalled) {
    # Fresh install - register the service
    Write-Log "Registering new Windows Service..."
    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        sc.exe delete $ServiceName | Out-Null
        Start-Sleep -Seconds 1
    }
    $serviceExe = "$InstallDir\Service\PCPlusService.exe"
    New-Service -Name $ServiceName `
        -BinaryPathName $serviceExe `
        -DisplayName "PC Plus Endpoint Protection" `
        -Description "PC Plus Endpoint Protection - Security monitoring, ransomware defense, system health." `
        -StartupType Automatic | Out-Null

    sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null
    Write-Log "Service registered."
}

# Start service
Write-Log "Starting service..."
Start-Service -Name $ServiceName
Write-Log "Service started."

# --- Set up tray app auto-start ---
$trayExe = "$InstallDir\Tray\PCPlusTray.exe"
if (Test-Path $trayExe) {
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    Set-ItemProperty -Path $regPath -Name "PCPlusEndpoint" -Value "`"$trayExe`""

    # Start tray for logged-in user
    Start-Process -FilePath $trayExe -WindowStyle Hidden -ErrorAction SilentlyContinue
    Write-Log "Tray app configured."
}

# --- Update uninstall registry ---
$uninstallKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\PCPlusEndpoint"
New-Item -Path $uninstallKey -Force | Out-Null
Set-ItemProperty -Path $uninstallKey -Name "DisplayName" -Value "PC Plus Endpoint Protection"
Set-ItemProperty -Path $uninstallKey -Name "DisplayVersion" -Value $targetVersion
Set-ItemProperty -Path $uninstallKey -Name "Publisher" -Value "PC Plus Computing"
Set-ItemProperty -Path $uninstallKey -Name "InstallLocation" -Value $InstallDir

# --- Cleanup ---
Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue

# --- Done ---
Write-Log "============================================="
if ($isInstalled) {
    Write-Log "UPDATE COMPLETE: $currentVersion -> $targetVersion"
} else {
    Write-Log "FRESH INSTALL COMPLETE: $targetVersion"
}
Write-Log "Customer: $($config['companyName'])"
Write-Log "Dashboard: $($config['dashboardApiUrl'])"
Write-Log "Security audit data will appear in dashboard within 30 seconds."
Write-Log "============================================="
