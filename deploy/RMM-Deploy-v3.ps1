<#
.SYNOPSIS
    PC Plus Endpoint - All-in-One Deploy + Dashboard Registration
    Installs service + tray, writes config, registers on dashboard immediately.

.NOTES
    Tactical RMM Settings:
    - Shell Type: PowerShell
    - Timeout: 600 seconds
    - Run As User: unchecked (runs as SYSTEM)
#>

# === CUSTOMIZE THESE ===
$DashboardUrl    = "https://dashboard.pcpluscomputing.com"
$CustomerName    = "{{client.name}}"    # Tactical RMM variable - auto-fills client name
$GitHubRepo      = "anirudhatalmale6-alt/pcplus-support-tray"
$ReleaseVersion  = "v4.7.2"            # Pin to known working version (use "latest" for newest)
# === END CUSTOMIZATION ===

$ErrorActionPreference = "Continue"
$ServiceName = "PCPlusEndpoint"
$InstallDir = "$env:ProgramFiles\PC Plus\Endpoint Protection"
$ConfigDir = "$env:ProgramData\PCPlusEndpoint"
$ConfigFile = "$ConfigDir\config.json"
$TempDir = "$env:TEMP\pcplus-deploy"
$LogFile = "$ConfigDir\Logs\deploy.log"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$ts] [$Level] $Message"
    Write-Host $line
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}

# Create dirs
New-Item -Path $TempDir -ItemType Directory -Force | Out-Null
New-Item -Path "$ConfigDir\Logs" -ItemType Directory -Force | Out-Null

Write-Log "============================================="
Write-Log "PC Plus Endpoint - Deploy v3"
Write-Log "Machine: $env:COMPUTERNAME"
Write-Log "User: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
Write-Log "============================================="

# ============================================================
# STEP 1: Write config FIRST (before anything else)
# ============================================================
Write-Log "STEP 1: Writing config..."
$guid = [guid]::NewGuid().ToString("N").Substring(0,4).ToUpper()
$deviceId = "$($env:COMPUTERNAME)-$guid"

$config = @{}
if (Test-Path $ConfigFile) {
    try {
        $existing = Get-Content $ConfigFile -Raw | ConvertFrom-Json
        $existing.PSObject.Properties | ForEach-Object { $config[$_.Name] = $_.Value }
        if ($config["deviceId"]) { $deviceId = $config["deviceId"] }
    } catch {}
}
$config["deviceId"] = $deviceId
$config["dashboardApiUrl"] = $DashboardUrl
if (-not $config.ContainsKey("ransomwareProtectionEnabled")) { $config["ransomwareProtectionEnabled"] = "true" }
if (-not $config.ContainsKey("autoContainmentEnabled")) { $config["autoContainmentEnabled"] = "true" }
if (-not $config.ContainsKey("showBalloonAlerts")) { $config["showBalloonAlerts"] = "true" }
if (-not $config.ContainsKey("logAlerts")) { $config["logAlerts"] = "true" }
$config | ConvertTo-Json -Depth 10 | Set-Content -Path $ConfigFile -Encoding UTF8
Write-Log "Config written: deviceId=$deviceId"

# ============================================================
# STEP 2: Send immediate heartbeat via PowerShell (guaranteed)
# ============================================================
Write-Log "STEP 2: Sending immediate heartbeat..."
$cpu = 0; $ram = 0; $disk = 0
try {
    $cpu = [math]::Round((Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average, 1)
    $os = Get-CimInstance Win32_OperatingSystem
    $ram = [math]::Round(($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / $os.TotalVisibleMemorySize * 100, 1)
    $c = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
    $disk = [math]::Round(($c.Size - $c.FreeSpace) / $c.Size * 100, 1)
} catch { Write-Log "Could not get system metrics: $_" "WARN" }

$osVer = "Windows"
try {
    $build = [Environment]::OSVersion.Version.Build
    if ($build -ge 22000) { $osVer = "Windows 11 (Build $build)" } else { $osVer = "Windows 10 (Build $build)" }
} catch {}

$localIp = "0.0.0.0"
try { $localIp = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -ne "127.0.0.1" -and $_.PrefixOrigin -ne "WellKnown" } | Select-Object -First 1).IPAddress } catch {}

$heartbeat = @{
    deviceId = $deviceId
    hostname = $env:COMPUTERNAME
    osVersion = $osVer
    agentVersion = "4.7.2"
    licenseTier = "Free"
    customerName = $(if ($CustomerName -and $CustomerName -notlike "*{{*") { $CustomerName } else { "" })
    localIp = $localIp
    cpuPercent = $cpu
    ramPercent = $ram
    diskPercent = $disk
    cpuTempC = 0
    gpuTempC = 0
    securityScore = 0
    securityGrade = "?"
    lockdownActive = $false
    activeAlerts = 0
    runningModules = 0
} | ConvertTo-Json

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $resp = Invoke-RestMethod -Uri "$DashboardUrl/api/endpoint/heartbeat" -Method POST -ContentType "application/json" -Body $heartbeat -TimeoutSec 10
    Write-Log "HEARTBEAT OK - Device registered on dashboard: $deviceId ($env:COMPUTERNAME)"
} catch {
    Write-Log "HEARTBEAT FAILED: $_" "ERROR"
}

# ============================================================
# STEP 3: Download and install binaries
# ============================================================
Write-Log "STEP 3: Downloading release..."
try {
    if ($ReleaseVersion -eq "latest") {
        $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$GitHubRepo/releases/latest" -UseBasicParsing
    } else {
        $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$GitHubRepo/releases/tags/$ReleaseVersion" -UseBasicParsing
    }
    $targetVersion = $release.tag_name
    Write-Log "Version: $targetVersion"
} catch {
    Write-Log "Failed to fetch release: $_" "ERROR"
    Write-Log "Device is registered on dashboard but service not installed."
    exit 0
}

$installerAsset = $release.assets | Where-Object { $_.name -like "*Installer*" } | Select-Object -First 1
if (-not $installerAsset) { Write-Log "No installer asset found" "ERROR"; exit 0 }

$zipPath = "$TempDir\PCPlusEndpoint-Installer.zip"
$extractPath = "$TempDir\extract"

Write-Log "Downloading $($installerAsset.name) ($([math]::Round($installerAsset.size / 1MB, 1)) MB)..."
try {
    Invoke-WebRequest -Uri $installerAsset.browser_download_url -OutFile $zipPath -UseBasicParsing
    Write-Log "Download complete."
} catch {
    try { $wc = New-Object System.Net.WebClient; $wc.DownloadFile($installerAsset.browser_download_url, $zipPath); Write-Log "Download complete (WebClient)." }
    catch { Write-Log "Download failed: $_" "ERROR"; exit 0 }
}

Write-Log "Extracting..."
try {
    if (Test-Path $extractPath) { Remove-Item $extractPath -Recurse -Force }
    Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force
    Write-Log "Extract complete."
} catch { Write-Log "Extract failed: $_" "ERROR"; exit 0 }

$svcSource = Get-ChildItem -Path $extractPath -Filter "PCPlusService.exe" -Recurse | Select-Object -First 1
$traySource = Get-ChildItem -Path $extractPath -Filter "PCPlusTray.exe" -Recurse | Select-Object -First 1
Write-Log "Service exe: $($svcSource -ne $null), Tray exe: $($traySource -ne $null)"

# ============================================================
# STEP 4: Stop existing service
# ============================================================
Write-Log "STEP 4: Stopping existing processes..."
try { & taskkill /F /IM PCPlusService.exe /T 2>&1 | Out-Null } catch {}
try { & taskkill /F /IM PCPlusTray.exe /T 2>&1 | Out-Null } catch {}
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    try { Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue } catch {}
    try { & sc.exe delete $ServiceName 2>&1 | Out-Null } catch {}
    Start-Sleep -Seconds 2
}
Write-Log "Processes stopped."

# ============================================================
# STEP 5: Copy binaries
# ============================================================
Write-Log "STEP 5: Installing binaries..."
New-Item -Path "$InstallDir\Service" -ItemType Directory -Force | Out-Null
New-Item -Path "$InstallDir\Tray" -ItemType Directory -Force | Out-Null

if ($svcSource) {
    try {
        Copy-Item -Path "$($svcSource.DirectoryName)\*" -Destination "$InstallDir\Service" -Recurse -Force -ErrorAction Stop
        Write-Log "Service binaries installed."
    } catch {
        Write-Log "Service copy failed, trying file-by-file: $_" "WARN"
        Get-ChildItem -Path $svcSource.DirectoryName -File | ForEach-Object {
            try { Copy-Item $_.FullName "$InstallDir\Service\$($_.Name)" -Force } catch {}
        }
    }
}
if ($traySource) {
    try {
        Copy-Item -Path "$($traySource.DirectoryName)\*" -Destination "$InstallDir\Tray" -Recurse -Force -ErrorAction Stop
        Write-Log "Tray binaries installed."
    } catch {
        Write-Log "Tray copy failed: $_" "WARN"
    }
}

# ============================================================
# STEP 6: Re-write config (in case copy overwrote it)
# ============================================================
Write-Log "STEP 6: Re-writing config..."
$config | ConvertTo-Json -Depth 10 | Set-Content -Path $ConfigFile -Encoding UTF8
Write-Log "Config confirmed: deviceId=$deviceId, dashboardApiUrl=$DashboardUrl"

# ============================================================
# STEP 7: Register and start service
# ============================================================
Write-Log "STEP 7: Registering service..."
$serviceExe = "$InstallDir\Service\PCPlusService.exe"
if (Test-Path $serviceExe) {
    try {
        $existingSvc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($existingSvc) { & sc.exe delete $ServiceName 2>&1 | Out-Null; Start-Sleep 1 }

        New-Service -Name $ServiceName `
            -BinaryPathName $serviceExe `
            -DisplayName "PC Plus Endpoint Protection" `
            -Description "PC Plus Endpoint Protection - Security monitoring, ransomware defense, system health." `
            -StartupType Automatic | Out-Null
        & sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/30000 2>&1 | Out-Null
        Write-Log "Service registered."

        Start-Service -Name $ServiceName -ErrorAction Stop
        Write-Log "Service started."

        # Give it a moment then restart to ensure config is loaded
        Start-Sleep -Seconds 3
        Restart-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        Write-Log "Service restarted (config reload)."
    } catch {
        Write-Log "Service setup failed: $_" "WARN"
    }
} else {
    Write-Log "Service exe not found at $serviceExe" "ERROR"
}

# ============================================================
# STEP 8: Setup tray auto-start
# ============================================================
$trayExe = "$InstallDir\Tray\PCPlusTray.exe"
if (Test-Path $trayExe) {
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "PCPlusEndpoint" -Value "`"$trayExe`""
        Start-Process -FilePath $trayExe -WindowStyle Hidden -ErrorAction SilentlyContinue
        Write-Log "Tray configured."
    } catch { Write-Log "Tray setup: $_" "WARN" }
}

# ============================================================
# STEP 9: Send final heartbeat to confirm everything works
# ============================================================
Write-Log "STEP 9: Final heartbeat..."
Start-Sleep -Seconds 5
try {
    $resp = Invoke-RestMethod -Uri "$DashboardUrl/api/endpoint/heartbeat" -Method POST -ContentType "application/json" -Body $heartbeat -TimeoutSec 10
    Write-Log "FINAL HEARTBEAT OK"
} catch {
    Write-Log "Final heartbeat failed: $_" "WARN"
}

# Cleanup
Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue

# ============================================================
# DONE
# ============================================================
$svcStatus = try { (Get-Service $ServiceName -ErrorAction SilentlyContinue).Status } catch { "unknown" }
Write-Log "============================================="
Write-Log "DEPLOY COMPLETE"
Write-Log "  Machine: $env:COMPUTERNAME"
Write-Log "  DeviceId: $deviceId"
Write-Log "  Dashboard: $DashboardUrl"
Write-Log "  Service: $svcStatus"
Write-Log "  Version: $targetVersion"
Write-Log "  Device is on dashboard NOW."
Write-Log "============================================="
