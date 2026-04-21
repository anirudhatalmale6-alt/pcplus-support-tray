<#
.SYNOPSIS
    PC Plus Endpoint Protection + Wazuh Agent - Combined Deploy Script
    Installs both services, writes config, registers on dashboard immediately.
    Heartbeat guaranteed every 30 seconds via Windows Scheduled Task.

.NOTES
    Tactical RMM Settings:
    - Shell Type: PowerShell
    - Timeout: 900 seconds
    - Run As User: unchecked (runs as SYSTEM)
    - Script Arguments: Pass customer name as first argument
      Example: In TRMM Script Arguments field, type: RLGF
      Or: -CustomerNameArg "RLGF"
#>

# Accept customer name as script argument from TRMM
param(
    [string]$CustomerNameArg = ""
)

# === CUSTOMIZE THESE ===
$DashboardUrl    = "https://dashboard.pcpluscomputing.com"
$CustomerName    = if ($CustomerNameArg) { $CustomerNameArg } else { "{{site.name}}" }
$TrmmApiKey      = "WDHX6IPCKJ9BISAFVOUJFFXVKKN5HMZV"
$TrmmApiUrl      = "https://api.pcpluscomputing.com"
$GitHubRepo      = "anirudhatalmale6-alt/pcplus-support-tray"
$ReleaseVersion  = "v4.15.0"           # Pin to known working version (use "latest" for newest)
$WazuhManager    = "184.68.146.18"
$WazuhVersion    = "4.11.2"
$WazuhAgentGroup = "default"
$HeartbeatIntervalSec = 30             # Dashboard heartbeat interval
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
New-Item -Path "$ConfigDir\Audits" -ItemType Directory -Force | Out-Null

Write-Log "============================================="
Write-Log "PC Plus Endpoint + Wazuh - Combined Deploy"
Write-Log "Machine: $env:COMPUTERNAME"
Write-Log "User: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
Write-Log "============================================="

# ============================================================
# STEP 0: Add antivirus exclusions (Avast, Windows Defender, AVG)
# ============================================================
Write-Log "STEP 0: Adding antivirus exclusions..."

# Paths to exclude
$ExcludePaths = @(
    "$env:ProgramFiles\PC Plus\Endpoint Protection",
    "$env:ProgramData\PCPlusEndpoint",
    "$env:ProgramData\PCPlusEndpoint\heartbeat.ps1",
    "$env:ProgramFiles\PC Plus\Endpoint Protection\Service\PCPlusService.exe",
    "$env:ProgramFiles\PC Plus\Endpoint Protection\Tray\PCPlusTray.exe"
)

# Windows Defender exclusions
foreach ($path in $ExcludePaths) {
    try { Add-MpPreference -ExclusionPath $path -ErrorAction SilentlyContinue } catch {}
}
try { Add-MpPreference -ExclusionProcess "PCPlusService.exe" -ErrorAction SilentlyContinue } catch {}
try { Add-MpPreference -ExclusionProcess "PCPlusTray.exe" -ErrorAction SilentlyContinue } catch {}
Write-Log "Windows Defender exclusions added."

# Avast exclusions (registry-based)
$avastExclPaths = @(
    "HKLM:\SOFTWARE\Avast Software\Avast\properties\ExcludedPaths",
    "HKLM:\SOFTWARE\AVAST Software\Avast\properties\ExcludedPaths"
)
foreach ($regPath in $avastExclPaths) {
    if (Test-Path (Split-Path $regPath)) {
        try { New-Item -Path $regPath -Force -ErrorAction SilentlyContinue | Out-Null } catch {}
        foreach ($path in $ExcludePaths) {
            try { New-ItemProperty -Path $regPath -Name $path -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null } catch {}
        }
        Write-Log "Avast exclusions added via registry."
    }
}

# Avast exclusions via config file (alternative method)
$avastIniPath = "$env:ProgramData\AVAST Software\Avast\avast5.ini"
if (Test-Path $avastIniPath) {
    try {
        $ini = Get-Content $avastIniPath -Raw -ErrorAction SilentlyContinue
        $needsUpdate = $false
        foreach ($path in $ExcludePaths) {
            $escapedPath = $path -replace '\\', '\\'
            if ($ini -notmatch [regex]::Escape($path)) { $needsUpdate = $true }
        }
        if ($needsUpdate) {
            $exclusionBlock = "`n[ExcludedPaths]`n"
            foreach ($path in $ExcludePaths) { $exclusionBlock += "$path`n" }
            Add-Content -Path $avastIniPath -Value $exclusionBlock -ErrorAction SilentlyContinue
            Write-Log "Avast exclusions added via config file."
        }
    } catch { Write-Log "Could not update Avast config: $_" "WARN" }
}

# AVG exclusions (same engine as Avast)
$avgExclPaths = @(
    "HKLM:\SOFTWARE\AVG\Antivirus\properties\ExcludedPaths",
    "HKLM:\SOFTWARE\AVG Software\AVG\properties\ExcludedPaths"
)
foreach ($regPath in $avgExclPaths) {
    if (Test-Path (Split-Path $regPath)) {
        try { New-Item -Path $regPath -Force -ErrorAction SilentlyContinue | Out-Null } catch {}
        foreach ($path in $ExcludePaths) {
            try { New-ItemProperty -Path $regPath -Name $path -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null } catch {}
        }
        Write-Log "AVG exclusions added."
    }
}

Write-Log "Antivirus exclusions complete."

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
# Set customer name - try multiple sources
$resolvedName = ""
# 1. From TRMM template variable or script argument (if it resolved)
if ($CustomerName -and $CustomerName -notlike "*{{*") { $resolvedName = $CustomerName }
# 2. Query TRMM API to get site name for this machine by hostname
if (-not $resolvedName -and $TrmmApiKey) {
    try {
        $headers = @{ "X-API-KEY" = $TrmmApiKey }
        $agents = Invoke-RestMethod -Uri "$TrmmApiUrl/agents/" -Headers $headers -TimeoutSec 10 -ErrorAction SilentlyContinue
        $thisAgent = $agents | Where-Object { $_.hostname -eq $env:COMPUTERNAME } | Select-Object -First 1
        if ($thisAgent -and $thisAgent.site_name) {
            $resolvedName = $thisAgent.site_name
            Write-Log "Customer name from TRMM API: '$resolvedName' (site for $env:COMPUTERNAME)"
        }
    } catch {
        Write-Log "TRMM API lookup failed: $_" "WARN"
    }
}
# 3. Keep existing config value if already set
if (-not $resolvedName -and $config["companyName"] -and $config["companyName"] -ne "PC Plus Computing") {
    $resolvedName = $config["companyName"]
}
if ($resolvedName) { $config["companyName"] = $resolvedName }
Write-Log "Customer name resolved: '$resolvedName'"
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

$resolvedCustomer = ""
if ($CustomerName -and $CustomerName -notlike "*{{*") { $resolvedCustomer = $CustomerName }

$heartbeat = @{
    deviceId = $deviceId
    hostname = $env:COMPUTERNAME
    osVersion = $osVer
    agentVersion = $ReleaseVersion.TrimStart("v")
    licenseTier = "Free"
    customerName = $resolvedCustomer
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
    Write-Log "HEARTBEAT OK - Device registered: $deviceId ($env:COMPUTERNAME)"
} catch {
    Write-Log "HEARTBEAT FAILED: $_" "ERROR"
}

# ============================================================
# STEP 3: Download and install Endpoint Protection binaries
# ============================================================
Write-Log "STEP 3: Downloading Endpoint Protection release..."
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    if ($ReleaseVersion -eq "latest") {
        $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$GitHubRepo/releases/latest" -UseBasicParsing
    } else {
        $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$GitHubRepo/releases/tags/$ReleaseVersion" -UseBasicParsing
    }
    $targetVersion = $release.tag_name
    Write-Log "Version: $targetVersion"
} catch {
    Write-Log "Failed to fetch release: $_" "ERROR"
    Write-Log "Device is registered on dashboard but service not installed. Continuing to Wazuh..."
    $targetVersion = $ReleaseVersion
    $release = $null
}

if ($release) {
    $installerAsset = $release.assets | Where-Object { $_.name -like "*Installer*" -and $_.name -like "*.zip" } | Select-Object -First 1
    if (-not $installerAsset) { $installerAsset = $release.assets | Where-Object { $_.name -like "*Installer*" } | Select-Object -First 1 }

    if ($installerAsset) {
        $zipPath = "$TempDir\PCPlusEndpoint-Installer.zip"
        $extractPath = "$TempDir\extract"

        Write-Log "Downloading $($installerAsset.name) ($([math]::Round($installerAsset.size / 1MB, 1)) MB)..."
        try {
            Invoke-WebRequest -Uri $installerAsset.browser_download_url -OutFile $zipPath -UseBasicParsing
            Write-Log "Download complete."
        } catch {
            try { $wc = New-Object System.Net.WebClient; $wc.DownloadFile($installerAsset.browser_download_url, $zipPath); Write-Log "Download complete (WebClient)." }
            catch { Write-Log "Download failed: $_" "ERROR"; $installerAsset = $null }
        }

        if ($installerAsset) {
            Write-Log "Extracting..."
            try {
                if (Test-Path $extractPath) { Remove-Item $extractPath -Recurse -Force }
                Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force
                Write-Log "Extract complete."
            } catch { Write-Log "Extract failed: $_" "ERROR"; $installerAsset = $null }
        }

        if ($installerAsset) {
            $svcSource = Get-ChildItem -Path $extractPath -Filter "PCPlusService.exe" -Recurse | Select-Object -First 1
            $traySource = Get-ChildItem -Path $extractPath -Filter "PCPlusTray.exe" -Recurse | Select-Object -First 1
            Write-Log "Service exe: $($svcSource -ne $null), Tray exe: $($traySource -ne $null)"

            # Stop existing processes
            Write-Log "Stopping existing Endpoint processes..."
            try { & taskkill /F /IM PCPlusService.exe /T 2>&1 | Out-Null } catch {}
            try { & taskkill /F /IM PCPlusTray.exe /T 2>&1 | Out-Null } catch {}
            $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
            if ($svc) {
                try { Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue } catch {}
                try { & sc.exe delete $ServiceName 2>&1 | Out-Null } catch {}
                Start-Sleep -Seconds 2
            }

            # Kill any running tray before copying new files
            Get-Process -Name "PCPlusTray" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 1

            # Copy binaries
            Write-Log "Installing Endpoint binaries..."
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
                } catch { Write-Log "Tray copy failed: $_" "WARN" }
            }

            # Re-write config (in case copy overwrote it)
            $config | ConvertTo-Json -Depth 10 | Set-Content -Path $ConfigFile -Encoding UTF8
            Write-Log "Config confirmed: deviceId=$deviceId"

            # Register and start service
            Write-Log "Registering Endpoint service..."
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

                    Start-Sleep -Seconds 3
                    Restart-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
                    Write-Log "Service restarted (config reload)."
                } catch {
                    Write-Log "Service setup failed: $_" "WARN"
                }
            } else {
                Write-Log "Service exe not found at $serviceExe" "ERROR"
            }

            # Setup tray auto-start (two methods for reliability)
            $trayExe = "$InstallDir\Tray\PCPlusTray.exe"
            if (Test-Path $trayExe) {
                try {
                    # Method 1: Registry Run key (starts on any user login)
                    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "PCPlusEndpoint" -Value "`"$trayExe`"" -ErrorAction SilentlyContinue
                    Write-Log "Tray configured for auto-start via registry."

                    # Method 2: Persistent logon-triggered scheduled task (backup for registry)
                    $persistTask = "PCPlusTrayAutoStart"
                    try { Unregister-ScheduledTask -TaskName $persistTask -Confirm:$false -ErrorAction SilentlyContinue } catch {}
                    $persistAction = New-ScheduledTaskAction -Execute $trayExe
                    $persistTrigger = New-ScheduledTaskTrigger -AtLogOn
                    $persistPrincipal = New-ScheduledTaskPrincipal -GroupId "BUILTIN\Users" -RunLevel Limited
                    $persistSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 0)
                    Register-ScheduledTask -TaskName $persistTask -Action $persistAction -Trigger $persistTrigger -Principal $persistPrincipal -Settings $persistSettings -Force | Out-Null
                    Write-Log "Persistent logon task '$persistTask' registered."

                    # Launch tray NOW in the logged-in user's session
                    $loggedOnUser = (Get-CimInstance Win32_ComputerSystem).UserName
                    if ($loggedOnUser) {
                        $taskName = "PCPlusTrayLaunch"
                        try { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue } catch {}
                        $trayAction = New-ScheduledTaskAction -Execute $trayExe
                        $trayTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(3)
                        $trayPrincipal = New-ScheduledTaskPrincipal -UserId $loggedOnUser -LogonType Interactive -RunLevel Limited
                        $traySettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
                        Register-ScheduledTask -TaskName $taskName -Action $trayAction -Trigger $trayTrigger -Principal $trayPrincipal -Settings $traySettings -Force | Out-Null
                        Start-Sleep -Seconds 2
                        Start-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
                        Start-Sleep -Seconds 5

                        # Verify with retry
                        $trayProc = Get-Process -Name "PCPlusTray" -ErrorAction SilentlyContinue
                        if (-not $trayProc) {
                            Write-Log "First launch attempt - retrying..." "WARN"
                            Start-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
                            Start-Sleep -Seconds 5
                            $trayProc = Get-Process -Name "PCPlusTray" -ErrorAction SilentlyContinue
                        }

                        if ($trayProc) {
                            Write-Log "Tray launched in user session: $loggedOnUser (PID: $($trayProc.Id))"
                        } else {
                            Write-Log "Tray not visible yet - will appear on next login via auto-start task" "WARN"
                        }
                    } else {
                        Write-Log "No user logged in - tray will start on next login via auto-start task."
                    }
                } catch { Write-Log "Tray setup: $_" "WARN" }
            }
        }
    } else {
        Write-Log "No installer asset found in release" "ERROR"
    }
}

# ============================================================
# STEP 4: Setup 30-second heartbeat via Scheduled Task
# ============================================================
Write-Log "STEP 4: Setting up 30-second heartbeat scheduled task..."

$heartbeatScript = @'
$ErrorActionPreference = "Continue"
$ConfigFile = "$env:ProgramData\PCPlusEndpoint\config.json"
$LogFile = "$env:ProgramData\PCPlusEndpoint\Logs\heartbeat.log"

if (-not (Test-Path $ConfigFile)) { exit 0 }

try {
    $cfg = Get-Content $ConfigFile -Raw | ConvertFrom-Json
    $dashUrl = $cfg.dashboardApiUrl
    $devId = $cfg.deviceId
    if (-not $dashUrl -or -not $devId) { exit 0 }

    $cpu = 0; $ram = 0; $disk = 0
    try {
        $cpu = [math]::Round((Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average, 1)
        $os = Get-CimInstance Win32_OperatingSystem
        $ram = [math]::Round(($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / $os.TotalVisibleMemorySize * 100, 1)
        $c = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
        $disk = [math]::Round(($c.Size - $c.FreeSpace) / $c.Size * 100, 1)
    } catch {}

    $osVer = "Windows"
    try {
        $build = [Environment]::OSVersion.Version.Build
        if ($build -ge 22000) { $osVer = "Windows 11 (Build $build)" } else { $osVer = "Windows 10 (Build $build)" }
    } catch {}

    $localIp = "0.0.0.0"
    try { $localIp = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -ne "127.0.0.1" -and $_.PrefixOrigin -ne "WellKnown" } | Select-Object -First 1).IPAddress } catch {}

    $svcStatus = try { (Get-Service PCPlusEndpoint -ErrorAction SilentlyContinue).Status.ToString() } catch { "Unknown" }
    $wazuhStatus = try { (Get-Service WazuhSvc -ErrorAction SilentlyContinue).Status.ToString() } catch { "NotInstalled" }

    $body = @{
        deviceId = $devId
        hostname = $env:COMPUTERNAME
        osVersion = $osVer
        agentVersion = "4.9.0"
        licenseTier = "Free"
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
        runningModules = $(if ($svcStatus -eq "Running") { 1 } else { 0 }) + $(if ($wazuhStatus -eq "Running") { 1 } else { 0 })
    } | ConvertTo-Json

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-RestMethod -Uri "$dashUrl/api/endpoint/heartbeat" -Method POST -ContentType "application/json" -Body $body -TimeoutSec 10 | Out-Null

    # Keep log small - only last line
    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') OK cpu=$cpu ram=$ram disk=$disk svc=$svcStatus wazuh=$wazuhStatus" | Set-Content $LogFile -Encoding UTF8
} catch {
    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') FAIL: $_" | Set-Content $LogFile -Encoding UTF8
}
'@

$heartbeatScriptPath = "$ConfigDir\heartbeat.ps1"
$heartbeatScript | Set-Content -Path $heartbeatScriptPath -Encoding UTF8
Write-Log "Heartbeat script written to $heartbeatScriptPath"

# Create scheduled task that runs every 30 seconds
# Windows Task Scheduler minimum repetition is 1 minute, so we create 2 tasks offset by 30 seconds
$taskName1 = "PCPlusHeartbeat"
$taskName2 = "PCPlusHeartbeat30"

# Remove existing tasks
try { Unregister-ScheduledTask -TaskName $taskName1 -Confirm:$false -ErrorAction SilentlyContinue } catch {}
try { Unregister-ScheduledTask -TaskName $taskName2 -Confirm:$false -ErrorAction SilentlyContinue } catch {}

$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$heartbeatScriptPath`""
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Seconds 25) -MultipleInstances IgnoreNew

# Task 1: Every 1 minute starting at :00
$trigger1 = New-ScheduledTaskTrigger -Once -At (Get-Date).Date -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration (New-TimeSpan -Days 9999)
try {
    Register-ScheduledTask -TaskName $taskName1 -Action $action -Principal $principal -Settings $settings -Trigger $trigger1 -Force | Out-Null
    Write-Log "Scheduled task '$taskName1' created (every 60s)."
} catch { Write-Log "Failed to create task $taskName1 : $_" "WARN" }

# Task 2: Every 1 minute starting at :30
$trigger2 = New-ScheduledTaskTrigger -Once -At (Get-Date).Date.AddSeconds(30) -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration (New-TimeSpan -Days 9999)
try {
    Register-ScheduledTask -TaskName $taskName2 -Action $action -Principal $principal -Settings $settings -Trigger $trigger2 -Force | Out-Null
    Write-Log "Scheduled task '$taskName2' created (every 60s, offset 30s)."
} catch { Write-Log "Failed to create task $taskName2 : $_" "WARN" }

Write-Log "Heartbeat guaranteed every 30 seconds via dual scheduled tasks."

# Run heartbeat immediately
try { Start-ScheduledTask -TaskName $taskName1 -ErrorAction SilentlyContinue } catch {}

# ============================================================
# STEP 5: Install Wazuh Agent
# ============================================================
Write-Log "STEP 5: Installing Wazuh Agent v$WazuhVersion..."

$WazuhServiceName = "WazuhSvc"
$WazuhInstallerUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-$WazuhVersion-1.msi"
$WazuhInstallerPath = "$TempDir\wazuh-agent.msi"

# Check if Wazuh is already installed and running
$existingWazuh = Get-Service -Name $WazuhServiceName -ErrorAction SilentlyContinue
if ($existingWazuh -and $existingWazuh.Status -eq "Running") {
    Write-Log "Wazuh Agent already installed and running. Checking manager config..."
    $ossecConf = "C:\Program Files (x86)\ossec-agent\ossec.conf"
    if (Test-Path $ossecConf) {
        $conf = Get-Content $ossecConf -Raw
        if ($conf -match "<address>([^<]+)</address>") {
            $configuredManager = $Matches[1]
            if ($configuredManager -ne $WazuhManager) {
                Write-Log "Updating Wazuh manager from $configuredManager to $WazuhManager..."
                $conf = $conf -replace "<address>[^<]+</address>", "<address>$WazuhManager</address>"
                Set-Content -Path $ossecConf -Value $conf -Encoding UTF8
                Restart-Service -Name $WazuhServiceName -ErrorAction SilentlyContinue
                Write-Log "Wazuh manager updated and restarted."
            } else {
                Write-Log "Wazuh already connected to correct manager: $WazuhManager"
            }
        }
    }
} else {
    # Download and install Wazuh
    Write-Log "Downloading Wazuh Agent v$WazuhVersion..."
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $wc = New-Object System.Net.WebClient
        $wc.DownloadFile($WazuhInstallerUrl, $WazuhInstallerPath)
        $fileSize = [math]::Round((Get-Item $WazuhInstallerPath).Length / 1MB, 1)
        Write-Log "Wazuh downloaded: $fileSize MB"
    } catch {
        try {
            Invoke-WebRequest -Uri $WazuhInstallerUrl -OutFile $WazuhInstallerPath -UseBasicParsing
            Write-Log "Wazuh downloaded (fallback)."
        } catch {
            Write-Log "Wazuh download failed: $_" "ERROR"
            $WazuhInstallerPath = $null
        }
    }

    if ($WazuhInstallerPath -and (Test-Path $WazuhInstallerPath)) {
        Write-Log "Installing Wazuh Agent..."
        try {
            $msiArgs = @(
                "/i", $WazuhInstallerPath,
                "/q",
                "WAZUH_MANAGER=$WazuhManager",
                "WAZUH_AGENT_NAME=$($env:COMPUTERNAME)",
                "WAZUH_AGENT_GROUP=$WazuhAgentGroup",
                "WAZUH_REGISTRATION_SERVER=$WazuhManager"
            )
            $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru -NoNewWindow
            if ($process.ExitCode -ne 0) {
                Write-Log "Wazuh MSI install exit code: $($process.ExitCode)" "WARN"
            } else {
                Write-Log "Wazuh installed successfully."
            }
        } catch {
            Write-Log "Wazuh install failed: $_" "ERROR"
        }

        # Start Wazuh service
        Start-Sleep -Seconds 3
        try {
            Start-Service -Name $WazuhServiceName -ErrorAction Stop
            Write-Log "Wazuh service started."
        } catch {
            Write-Log "Wazuh service start: $_" "WARN"
            Start-Sleep -Seconds 5
            try { Start-Service -Name $WazuhServiceName -ErrorAction SilentlyContinue } catch {}
        }

        # Cleanup
        Remove-Item -Path $WazuhInstallerPath -Force -ErrorAction SilentlyContinue
    }
}

# ============================================================
# STEP 6: Send final heartbeat to confirm everything works
# ============================================================
Write-Log "STEP 6: Final heartbeat..."
Start-Sleep -Seconds 5
try {
    $resp = Invoke-RestMethod -Uri "$DashboardUrl/api/endpoint/heartbeat" -Method POST -ContentType "application/json" -Body $heartbeat -TimeoutSec 10
    Write-Log "FINAL HEARTBEAT OK"
} catch {
    Write-Log "Final heartbeat failed: $_" "WARN"
}

# Cleanup temp
Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue

# ============================================================
# SUMMARY
# ============================================================
$epStatus = try { (Get-Service $ServiceName -ErrorAction SilentlyContinue).Status } catch { "unknown" }
$wzStatus = try { (Get-Service $WazuhServiceName -ErrorAction SilentlyContinue).Status } catch { "not installed" }
$task1 = try { (Get-ScheduledTask -TaskName $taskName1 -ErrorAction SilentlyContinue).State } catch { "not found" }

Write-Log "============================================="
Write-Log "DEPLOY COMPLETE"
Write-Log "  Machine:    $env:COMPUTERNAME"
Write-Log "  DeviceId:   $deviceId"
Write-Log "  Customer:   $(if($resolvedCustomer){"$resolvedCustomer"}else{"(auto-detect)"})"
Write-Log "  Dashboard:  $DashboardUrl"
Write-Log "  Endpoint:   $epStatus"
Write-Log "  Wazuh:      $wzStatus"
Write-Log "  Heartbeat:  Every 30s (task: $task1)"
Write-Log "  Version:    $targetVersion"
Write-Log "  Device is on dashboard NOW."
Write-Log "============================================="
