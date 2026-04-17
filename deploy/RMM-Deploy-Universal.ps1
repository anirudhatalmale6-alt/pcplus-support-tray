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

$ErrorActionPreference = "Continue"
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
Write-Log "Running as: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"

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
    Write-Log "Download failed: $_" "WARN"
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
try {
    if (Test-Path $extractPath) { Remove-Item $extractPath -Recurse -Force }
    Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force
    Write-Log "Extract complete."
} catch {
    Write-Log "Extract failed: $_" "ERROR"
    exit 1
}

# Find binaries
$svcSource = Get-ChildItem -Path $extractPath -Filter "PCPlusService.exe" -Recurse | Select-Object -First 1
$traySource = Get-ChildItem -Path $extractPath -Filter "PCPlusTray.exe" -Recurse | Select-Object -First 1

Write-Log "Service exe found: $($svcSource -ne $null) ($($svcSource.FullName))"
Write-Log "Tray exe found: $($traySource -ne $null) ($($traySource.FullName))"

if (-not $svcSource) {
    Write-Log "PCPlusService.exe not found in download" "ERROR"
    exit 1
}

# --- Stop existing service and tray ---
Write-Log "Stopping existing processes..."
try { & taskkill /F /IM PCPlusService.exe /T 2>&1 | Out-Null } catch {}
try { & taskkill /F /IM PCPlusTray.exe /T 2>&1 | Out-Null } catch {}
Write-Log "Taskkill done."

$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    Write-Log "Stopping existing service..."
    try { Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue } catch {}
    try { & sc.exe delete $ServiceName 2>&1 | Out-Null } catch {}
    Start-Sleep -Seconds 2
}
Write-Log "Existing processes stopped."

# --- Create directories ---
Write-Log "Creating install directories..."
New-Item -Path "$InstallDir\Service" -ItemType Directory -Force | Out-Null
New-Item -Path "$InstallDir\Tray" -ItemType Directory -Force | Out-Null
New-Item -Path "$ConfigDir\Audits" -ItemType Directory -Force | Out-Null
Write-Log "Directories created."

# --- Copy binaries ---
Write-Log "Installing service binaries from $($svcSource.DirectoryName)..."
try {
    Copy-Item -Path "$($svcSource.DirectoryName)\*" -Destination "$InstallDir\Service" -Recurse -Force -ErrorAction Stop
    Write-Log "Service binaries installed."
} catch {
    Write-Log "Service copy failed: $_" "ERROR"
    # Try file-by-file
    Write-Log "Trying file-by-file copy..."
    Get-ChildItem -Path $svcSource.DirectoryName -File | ForEach-Object {
        try {
            Copy-Item -Path $_.FullName -Destination "$InstallDir\Service\$($_.Name)" -Force
        } catch {
            Write-Log "  Failed to copy $($_.Name): $_" "WARN"
        }
    }
}

if ($traySource) {
    Write-Log "Installing tray binaries from $($traySource.DirectoryName)..."
    try {
        Copy-Item -Path "$($traySource.DirectoryName)\*" -Destination "$InstallDir\Tray" -Recurse -Force -ErrorAction Stop
        Write-Log "Tray binaries installed."
    } catch {
        Write-Log "Tray copy failed: $_" "ERROR"
        Get-ChildItem -Path $traySource.DirectoryName -File | ForEach-Object {
            try {
                Copy-Item -Path $_.FullName -Destination "$InstallDir\Tray\$($_.Name)" -Force
            } catch {
                Write-Log "  Failed to copy $($_.Name): $_" "WARN"
            }
        }
    }
}

# --- Write/update config (preserve existing values) ---
Write-Log "Writing config..."
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
Write-Log "Registering Windows Service..."
try {
    # Clean up any existing registration
    $existingSvc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($existingSvc) {
        & sc.exe delete $ServiceName 2>&1 | Out-Null
        Start-Sleep -Seconds 1
    }

    $serviceExe = "$InstallDir\Service\PCPlusService.exe"
    if (Test-Path $serviceExe) {
        New-Service -Name $ServiceName `
            -BinaryPathName $serviceExe `
            -DisplayName "PC Plus Endpoint Protection" `
            -Description "PC Plus Endpoint Protection - Security monitoring, ransomware defense, system health." `
            -StartupType Automatic | Out-Null
        Write-Log "Service registered."

        & sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/30000 2>&1 | Out-Null

        # Start service
        Write-Log "Starting service..."
        try {
            Start-Service -Name $ServiceName -ErrorAction Stop
            Write-Log "Service started successfully."
        } catch {
            Write-Log "Service failed to start: $_" "WARN"
            Write-Log "Service may start on next reboot."
        }
    } else {
        Write-Log "Service exe not found at $serviceExe" "ERROR"
    }
} catch {
    Write-Log "Service registration failed: $_" "ERROR"
}

# --- Set up tray app auto-start ---
$trayExe = "$InstallDir\Tray\PCPlusTray.exe"
if (Test-Path $trayExe) {
    Write-Log "Configuring tray app auto-start..."
    try {
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        Set-ItemProperty -Path $regPath -Name "PCPlusEndpoint" -Value "`"$trayExe`""
        Write-Log "Tray app auto-start configured."
    } catch {
        Write-Log "Failed to set auto-start: $_" "WARN"
    }

    # Start tray for logged-in user
    try {
        Start-Process -FilePath $trayExe -WindowStyle Hidden -ErrorAction SilentlyContinue
        Write-Log "Tray app started."
    } catch {
        Write-Log "Could not start tray app (no user logged in?): $_" "WARN"
    }
} else {
    Write-Log "Tray exe not found at $trayExe" "WARN"
}

# --- Update uninstall registry ---
Write-Log "Updating uninstall registry..."
try {
    $uninstallKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\PCPlusEndpoint"
    New-Item -Path $uninstallKey -Force | Out-Null
    Set-ItemProperty -Path $uninstallKey -Name "DisplayName" -Value "PC Plus Endpoint Protection"
    Set-ItemProperty -Path $uninstallKey -Name "DisplayVersion" -Value $targetVersion
    Set-ItemProperty -Path $uninstallKey -Name "Publisher" -Value "PC Plus Computing"
    Set-ItemProperty -Path $uninstallKey -Name "InstallLocation" -Value $InstallDir
    Write-Log "Uninstall registry updated."
} catch {
    Write-Log "Failed to update uninstall registry: $_" "WARN"
}

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
Write-Log "Service: $(try { (Get-Service $ServiceName -ErrorAction SilentlyContinue).Status } catch { 'unknown' })"
Write-Log "Security audit data will appear in dashboard within 30 seconds."
Write-Log "============================================="
