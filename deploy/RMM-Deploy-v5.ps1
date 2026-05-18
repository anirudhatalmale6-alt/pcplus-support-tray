# PC Plus Endpoint Protection v5.9.9 - Robust RMM Deployment Script
# Handles: Avast exclusions, stubborn service processes, forced reboot+auto-resume
# Run via Tactical RMM as PowerShell script (Run as System)
# Set $Tier below to match the customer's subscription (Free, Standard, Premium)

$ErrorActionPreference = 'Stop'
$Version = "5.10.0"
$Tier = "Premium"
$InstallDir = "C:\Program Files\PC Plus\Endpoint Protection"
$DataDir = "C:\ProgramData\PCPlusEndpoint"
$LogFile = "C:\ProgramData\PCPlusEndpoint\Logs\deploy.log"
$DownloadUrl = "https://github.com/anirudhatalmale6-alt/pcplus-support-tray/releases/download/v$Version/PCPlusEndpoint-Setup-$Version.exe"
$TempExe = "$env:TEMP\PCPlusEndpoint-Setup-$Version.exe"
$ResumeFlag = "$DataDir\deploy-resume.flag"
$TaskName = "PCPlusDeployResume"

function Log($msg) {
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$ts] $msg"
    Write-Host $line
    New-Item -Path (Split-Path $LogFile) -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}

function Test-ServiceProcessRunning {
    $svc = Get-WmiObject Win32_Service -Filter "Name='PCPlusEndpoint'" -ErrorAction SilentlyContinue
    if ($svc -and $svc.ProcessId -and $svc.ProcessId -ne 0) {
        $proc = Get-Process -Id $svc.ProcessId -ErrorAction SilentlyContinue
        if ($proc) { return $svc.ProcessId }
    }
    $procs = Get-Process -Name "PCPlusService" -ErrorAction SilentlyContinue
    if ($procs) { return $procs[0].Id }
    return 0
}

function Stop-ServiceAggressive {
    Log "Phase 1: Stopping service..."

    # Kill tray first
    Get-Process -Name "PCPlusTray" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

    # Try graceful stop
    Stop-Service -Name "PCPlusEndpoint" -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3

    $pid = Test-ServiceProcessRunning
    if ($pid -eq 0) {
        Log "Service stopped gracefully"
        return $true
    }

    # Try sc delete (marks for deletion, releases the service name)
    Log "Phase 2: sc delete + force kill PID $pid..."
    sc.exe delete PCPlusEndpoint 2>$null
    Start-Sleep -Seconds 2

    # Force kill the process
    taskkill /F /PID $pid 2>$null
    Start-Sleep -Seconds 2

    $pid = Test-ServiceProcessRunning
    if ($pid -eq 0) {
        Log "Service killed after sc delete"
        return $true
    }

    # Try WMI terminate
    Log "Phase 3: WMI terminate PID $pid..."
    try {
        $proc = Get-WmiObject Win32_Process -Filter "ProcessId=$pid"
        if ($proc) { $proc.Terminate() | Out-Null }
    } catch {
        Log "WMI terminate failed: $_"
    }
    Start-Sleep -Seconds 2

    $pid = Test-ServiceProcessRunning
    if ($pid -eq 0) {
        Log "Service killed via WMI"
        return $true
    }

    Log "WARNING: Service process PID $pid could not be killed"
    return $false
}

# Check if this is a post-reboot resume
$isResume = Test-Path $ResumeFlag
if ($isResume) {
    Log "=== POST-REBOOT RESUME ==="
    Remove-Item $ResumeFlag -Force -ErrorAction SilentlyContinue
    # Remove scheduled task
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    # Service should be gone after reboot, proceed to install
}

# Check if already on target version
$currentExe = "$InstallDir\Service\PCPlusService.exe"
if (Test-Path $currentExe) {
    $currentVersion = (Get-Item $currentExe).VersionInfo.ProductVersion
    if ($currentVersion -and $currentVersion.StartsWith($Version)) {
        # Also verify service is running
        $svcStatus = (Get-Service -Name "PCPlusEndpoint" -ErrorAction SilentlyContinue).Status
        if ($svcStatus -eq "Running") {
            Log "Already on v$Version and service is running. Skipping."
            exit 0
        }
        Log "Version matches but service status: $svcStatus. Will reinstall."
    } else {
        Log "Current version: $currentVersion, upgrading to $Version"
    }
}

Log "Starting PC Plus Endpoint v$Version deployment"

# Step 1: AV exclusions (Avast + Defender)
$avastFound = $false
$avastRegPaths = @(
    "HKLM:\SOFTWARE\Avast Software\Avast\properties",
    "HKLM:\SOFTWARE\AVAST Software\Avast\properties"
)
foreach ($regPath in $avastRegPaths) {
    if (Test-Path $regPath) {
        $avastFound = $true
        Log "Avast detected at $regPath"
        $excludePaths = @($InstallDir, $DataDir, $TempExe)
        foreach ($p in $excludePaths) {
            try {
                $existing = (Get-ItemProperty -Path $regPath -Name "ExcludedPaths" -ErrorAction SilentlyContinue).ExcludedPaths
                if ($existing -and $existing -notlike "*$p*") {
                    Set-ItemProperty -Path $regPath -Name "ExcludedPaths" -Value "$existing;$p"
                } elseif (-not $existing) {
                    New-ItemProperty -Path $regPath -Name "ExcludedPaths" -Value $p -PropertyType String -Force | Out-Null
                }
            } catch { Log "Registry exclusion warning: $_" }
        }
        Log "Avast registry exclusions added"
        break
    }
}

$avastCli = "C:\Program Files\Avast Software\Avast\ashCmd.exe"
if (Test-Path $avastCli) {
    $avastFound = $true
    try {
        & $avastCli /AddExclude:Path:$InstallDir 2>$null
        & $avastCli /AddExclude:Path:$DataDir 2>$null
        & $avastCli /AddExclude:Path:$TempExe 2>$null
        Log "Avast CLI exclusions added"
    } catch { Log "Avast CLI warning: $_" }
}

if ($avastFound) { Start-Sleep -Seconds 5 }

try {
    Add-MpPreference -ExclusionPath $InstallDir -ErrorAction SilentlyContinue
    Add-MpPreference -ExclusionPath $DataDir -ErrorAction SilentlyContinue
    Log "Defender exclusions added"
} catch { Log "Defender exclusion warning: $_" }

# Step 2: Stop existing service
if (-not $isResume) {
    $killed = Stop-ServiceAggressive
    if (-not $killed) {
        Log "Service process is stubborn. Setting up post-reboot auto-install..."

        # Download installer now (before reboot) so it's ready
        Log "Pre-downloading installer for post-reboot..."
        try {
            $curlPath = Get-Command curl.exe -ErrorAction SilentlyContinue
            if ($curlPath) {
                & curl.exe --ssl-no-revoke -L -o $TempExe $DownloadUrl 2>&1 | Out-Null
            } else {
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                (New-Object System.Net.WebClient).DownloadFile($DownloadUrl, $TempExe)
            }
            $size = (Get-Item $TempExe).Length / 1MB
            Log "Pre-downloaded $([math]::Round($size,1)) MB"
        } catch {
            Log "Pre-download failed, will download after reboot: $_"
        }

        # Create resume flag
        New-Item -Path $DataDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
        "resume" | Set-Content $ResumeFlag -Force

        # Create scheduled task to re-run this script after reboot
        $scriptPath = "$DataDir\deploy-resume.ps1"
        @"
# Auto-generated resume script - runs once after reboot
`$ErrorActionPreference = 'Stop'
`$LogFile = "$LogFile"
function Log(`$msg) { `$ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"; `$line = "[`$ts] `$msg"; Write-Host `$line; Add-Content -Path `$LogFile -Value `$line -ErrorAction SilentlyContinue }

Log "Post-reboot: waiting 30 seconds for system to settle..."
Start-Sleep -Seconds 30

`$TempExe = "$TempExe"
`$Version = "$Version"
`$DownloadUrl = "$DownloadUrl"
`$InstallDir = "$InstallDir"
`$DataDir = "$DataDir"
`$Tier = "$Tier"

# Download if not already present
if (-not (Test-Path `$TempExe) -or (Get-Item `$TempExe).Length -lt 50MB) {
    Log "Downloading installer..."
    try {
        `$curlPath = Get-Command curl.exe -ErrorAction SilentlyContinue
        if (`$curlPath) {
            & curl.exe --ssl-no-revoke -L -o `$TempExe `$DownloadUrl 2>&1 | Out-Null
        } else {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            (New-Object System.Net.WebClient).DownloadFile(`$DownloadUrl, `$TempExe)
        }
    } catch { Log "Download failed: `$_"; exit 1 }
}

# Run installer
Log "Running installer..."
`$proc = Start-Process -FilePath `$TempExe -ArgumentList "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART" -Wait -PassThru
Log "Installer exit code: `$(`$proc.ExitCode)"

# Verify
Start-Sleep -Seconds 5
`$svcStatus = (Get-Service -Name "PCPlusEndpoint" -ErrorAction SilentlyContinue).Status
if (`$svcStatus -ne "Running") {
    Start-Service -Name "PCPlusEndpoint" -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3
    `$svcStatus = (Get-Service -Name "PCPlusEndpoint" -ErrorAction SilentlyContinue).Status
}

# Set tier
`$configFile = "`$DataDir\config.json"
if (Test-Path `$configFile) {
    `$config = Get-Content `$configFile -Raw | ConvertFrom-Json
} else {
    `$config = [PSCustomObject]@{}
}
`$config | Add-Member -NotePropertyName "activeTier" -NotePropertyValue `$Tier -Force
`$config | Add-Member -NotePropertyName "adguardHomeUrl" -NotePropertyValue "https://dns.pcpluscomputing.com" -Force
`$config | Add-Member -NotePropertyName "adguardHomeUser" -NotePropertyValue "admin" -Force
`$config | ConvertTo-Json -Depth 10 | Set-Content `$configFile -Encoding UTF8

# Cleanup
Remove-Item `$TempExe -Force -ErrorAction SilentlyContinue
Remove-Item "$ResumeFlag" -Force -ErrorAction SilentlyContinue
Remove-Item "`$PSCommandPath" -Force -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName "$TaskName" -Confirm:`$false -ErrorAction SilentlyContinue

`$exeVer = (Get-Item "`$InstallDir\Service\PCPlusService.exe" -ErrorAction SilentlyContinue).VersionInfo.ProductVersion
Log "POST-REBOOT DEPLOY COMPLETE. Service: `$svcStatus, Version: `$exeVer"
"@ | Set-Content $scriptPath -Encoding UTF8

        $action = New-ScheduledTaskAction -Execute "powershell.exe" `
            -Argument "-ExecutionPolicy Bypass -File `"$scriptPath`""
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest -LogonType ServiceAccount
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
            -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
            -Principal $principal -Settings $settings -Force | Out-Null

        Log "Scheduled task '$TaskName' created. Rebooting in 10 seconds..."
        shutdown /r /t 10 /c "PC Plus Endpoint update - rebooting to complete installation" /f
        exit 0
    }
} else {
    # Post-reboot resume: verify service is gone
    $pid = Test-ServiceProcessRunning
    if ($pid -ne 0) {
        Log "Post-reboot but process still running (PID $pid). Attempting kill..."
        taskkill /F /PID $pid 2>$null
        Start-Sleep -Seconds 3
    }
}

# Step 3: Download installer (skip if already downloaded for resume)
if (-not (Test-Path $TempExe) -or (Get-Item $TempExe).Length -lt 50MB) {
    Log "Downloading installer from GitHub..."
    try {
        $curlPath = Get-Command curl.exe -ErrorAction SilentlyContinue
        if ($curlPath) {
            & curl.exe --ssl-no-revoke -L -o $TempExe $DownloadUrl 2>&1 | Out-Null
        } else {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            (New-Object System.Net.WebClient).DownloadFile($DownloadUrl, $TempExe)
        }
        $size = (Get-Item $TempExe).Length / 1MB
        Log "Downloaded $([math]::Round($size,1)) MB"
        if ($size -lt 50) {
            Log "ERROR: Download incomplete ($([math]::Round($size,1)) MB, expected ~69 MB)"
            exit 1
        }
    } catch {
        Log "ERROR: Download failed - $_"
        exit 1
    }
} else {
    $size = (Get-Item $TempExe).Length / 1MB
    Log "Using pre-downloaded installer ($([math]::Round($size,1)) MB)"
}

# Step 4: Run installer silently
Log "Running installer..."
try {
    $proc = Start-Process -FilePath $TempExe -ArgumentList "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART" -Wait -PassThru
    Log "Installer exit code: $($proc.ExitCode)"
    if ($proc.ExitCode -ne 0) {
        Log "WARNING: Non-zero exit code $($proc.ExitCode)"
    }
} catch {
    Log "ERROR: Installer failed - $_"
    exit 1
}

# Step 5: Verify installation
Start-Sleep -Seconds 5
$svcStatus = (Get-Service -Name "PCPlusEndpoint" -ErrorAction SilentlyContinue).Status
if ($svcStatus -eq "Running") {
    Log "Service is running"
} elseif ($svcStatus) {
    Log "Service status: $svcStatus. Starting..."
    Start-Service -Name "PCPlusEndpoint" -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3
    $svcStatus = (Get-Service -Name "PCPlusEndpoint" -ErrorAction SilentlyContinue).Status
    Log "Service status after start: $svcStatus"
} else {
    Log "Service not found. Registering manually..."
    $svcExe = "$InstallDir\Service\PCPlusService.exe"
    if (Test-Path $svcExe) {
        sc.exe create PCPlusEndpoint binPath= "`"$svcExe`"" start= auto DisplayName= "PC Plus Endpoint Protection"
        sc.exe failure PCPlusEndpoint reset= 86400 actions= restart/5000/restart/10000/restart/30000
        Start-Service -Name "PCPlusEndpoint" -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
        $svcStatus = (Get-Service -Name "PCPlusEndpoint" -ErrorAction SilentlyContinue).Status
        Log "Manual registration: $svcStatus"
    } else {
        Log "ERROR: Service exe not found at $svcExe"
        exit 1
    }
}

# Step 6: Start tray for logged-in user
$trayExe = "$InstallDir\Tray\PCPlusTray.exe"
if (Test-Path $trayExe) {
    $loggedOnUser = (Get-WmiObject -Class Win32_ComputerSystem).UserName
    if ($loggedOnUser) {
        try {
            Start-Process -FilePath $trayExe -ErrorAction SilentlyContinue
            Log "Tray started"
        } catch { Log "Tray start warning: $_" }
    }
}

# Step 7: Set config (tier + AdGuard Home URL)
$configFile = "$DataDir\config.json"
try {
    if (Test-Path $configFile) {
        $config = Get-Content $configFile -Raw | ConvertFrom-Json
    } else {
        $config = [PSCustomObject]@{}
    }
    $config | Add-Member -NotePropertyName "activeTier" -NotePropertyValue $Tier -Force
    $config | Add-Member -NotePropertyName "adguardHomeUrl" -NotePropertyValue "https://dns.pcpluscomputing.com" -Force
    $config | Add-Member -NotePropertyName "adguardHomeUser" -NotePropertyValue "admin" -Force
    $config | ConvertTo-Json -Depth 10 | Set-Content $configFile -Encoding UTF8
    Log "Config updated: tier=$Tier, adguardHomeUrl=dns.pcpluscomputing.com"
} catch { Log "Config update warning: $_" }

# Step 8: Verify version
$exeVersion = (Get-Item "$InstallDir\Service\PCPlusService.exe" -ErrorAction SilentlyContinue).VersionInfo.ProductVersion
Log "Installed version: $exeVersion"

# Cleanup
Remove-Item $TempExe -Force -ErrorAction SilentlyContinue

Log "=== DEPLOYMENT COMPLETE === Service: $svcStatus, Version: $exeVersion"
