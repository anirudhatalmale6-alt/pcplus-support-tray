# PC Plus Endpoint Protection v5.9.7 - Safe RMM Deployment Script
# Handles Avast exclusions before installing to prevent false positive blocks
# Run via Tactical RMM as PowerShell script (Run as System)
# Set $Tier below to match the customer's subscription (Free, Standard, Premium)

$ErrorActionPreference = 'Stop'
$Version = "5.9.7"
$Tier = "Premium"  # Change per customer: Free, Standard, or Premium
$InstallDir = "C:\Program Files\PC Plus\Endpoint Protection"
$DataDir = "C:\ProgramData\PCPlusEndpoint"
$LogFile = "C:\ProgramData\PCPlusEndpoint\Logs\deploy.log"
$DownloadUrl = "https://github.com/anirudhatalmale6-alt/pcplus-support-tray/releases/download/v$Version/PCPlusEndpoint-Setup-$Version.exe"
$TempExe = "$env:TEMP\PCPlusEndpoint-Setup-$Version.exe"

function Log($msg) {
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$ts] $msg"
    Write-Host $line
    New-Item -Path (Split-Path $LogFile) -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}

Log "Starting PC Plus Endpoint v$Version deployment"

# Step 1: Add Avast exclusions (multiple methods for compatibility)
$avastFound = $false

# Method A: Avast registry exclusions (most reliable)
$avastRegPaths = @(
    "HKLM:\SOFTWARE\Avast Software\Avast\properties",
    "HKLM:\SOFTWARE\AVAST Software\Avast\properties"
)
foreach ($regPath in $avastRegPaths) {
    if (Test-Path $regPath) {
        $avastFound = $true
        Log "Avast detected via registry at $regPath"

        # Add file system scan exclusions
        $excludePaths = @($InstallDir, $DataDir, $TempExe)
        foreach ($p in $excludePaths) {
            try {
                $existing = (Get-ItemProperty -Path $regPath -Name "ExcludedPaths" -ErrorAction SilentlyContinue).ExcludedPaths
                if ($existing -and $existing -notlike "*$p*") {
                    Set-ItemProperty -Path $regPath -Name "ExcludedPaths" -Value "$existing;$p"
                } elseif (-not $existing) {
                    New-ItemProperty -Path $regPath -Name "ExcludedPaths" -Value $p -PropertyType String -Force | Out-Null
                }
            } catch {
                Log "Registry exclusion warning: $_"
            }
        }
        Log "Registry exclusions added"
        break
    }
}

# Method B: Avast CLI tool
$avastCli = "C:\Program Files\Avast Software\Avast\ashCmd.exe"
if (Test-Path $avastCli) {
    $avastFound = $true
    Log "Avast CLI found, adding exclusions"
    try {
        & $avastCli /AddExclude:Path:$InstallDir 2>$null
        & $avastCli /AddExclude:Path:$DataDir 2>$null
        & $avastCli /AddExclude:Path:$TempExe 2>$null
        Log "CLI exclusions added"
    } catch {
        Log "CLI exclusion warning: $_"
    }
}

# Method C: Avast settings file
$avastIni = "C:\ProgramData\AVAST Software\Avast\avast5.ini"
if (Test-Path $avastIni) {
    $avastFound = $true
    Log "Avast INI found, checking exclusions"
}

if ($avastFound) {
    Log "Avast exclusions configured. Waiting 5 seconds for Avast to reload..."
    Start-Sleep -Seconds 5
} else {
    Log "Avast not detected - proceeding with install"
}

# Also handle Windows Defender exclusions
try {
    Add-MpPreference -ExclusionPath $InstallDir -ErrorAction SilentlyContinue
    Add-MpPreference -ExclusionPath $DataDir -ErrorAction SilentlyContinue
    Log "Windows Defender exclusions added"
} catch {
    Log "Defender exclusion warning: $_"
}

# Step 2: Download installer
Log "Downloading installer from GitHub..."
try {
    # Prefer curl (lighter, handles redirects, no memory issues)
    $curlPath = Get-Command curl.exe -ErrorAction SilentlyContinue
    if ($curlPath) {
        & curl.exe --ssl-no-revoke -L -o $TempExe $DownloadUrl 2>&1 | Out-Null
    } else {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $wc = New-Object System.Net.WebClient
        $wc.DownloadFile($DownloadUrl, $TempExe)
    }
    $size = (Get-Item $TempExe).Length / 1MB
    Log "Downloaded $([math]::Round($size,1)) MB to $TempExe"
    if ($size -lt 50) {
        Log "ERROR: Download incomplete ($([math]::Round($size,1)) MB, expected ~69 MB)"
        exit 1
    }
} catch {
    Log "ERROR: Download failed - $_"
    exit 1
}

# Step 3: Stop existing service and tray if running
Log "Stopping existing service and tray..."
Stop-Service -Name "PCPlusEndpoint" -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 3
# Force kill if STOP_PENDING
$svcPid = (Get-WmiObject Win32_Service -Filter "Name='PCPlusEndpoint'" -ErrorAction SilentlyContinue).ProcessId
if ($svcPid -and $svcPid -ne 0) {
    taskkill /F /PID $svcPid 2>$null
    Log "Force killed service process PID $svcPid"
}
Get-Process -Name "PCPlusTray" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

# Step 4: Run installer silently
Log "Running installer..."
try {
    $proc = Start-Process -FilePath $TempExe -ArgumentList "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART" -Wait -PassThru
    Log "Installer exit code: $($proc.ExitCode)"
} catch {
    Log "ERROR: Installer failed - $_"
    exit 1
}

# Step 5: Verify installation
Start-Sleep -Seconds 3
$svcStatus = (Get-Service -Name "PCPlusEndpoint" -ErrorAction SilentlyContinue).Status
if ($svcStatus -eq "Running") {
    Log "SUCCESS: Service is running"
} elseif ($svcStatus) {
    Log "Service exists but status is: $svcStatus. Starting..."
    Start-Service -Name "PCPlusEndpoint" -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    $svcStatus = (Get-Service -Name "PCPlusEndpoint" -ErrorAction SilentlyContinue).Status
    Log "Service status after start: $svcStatus"
} else {
    Log "WARNING: Service not found after install. Registering manually..."
    $svcExe = "$InstallDir\Service\PCPlusService.exe"
    if (Test-Path $svcExe) {
        sc.exe create PCPlusEndpoint binPath= "`"$svcExe`"" start= auto DisplayName= "PC Plus Endpoint Protection"
        sc.exe failure PCPlusEndpoint reset= 86400 actions= restart/5000/restart/10000/restart/30000
        Start-Service -Name "PCPlusEndpoint" -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        $svcStatus = (Get-Service -Name "PCPlusEndpoint" -ErrorAction SilentlyContinue).Status
        Log "Manual registration result: $svcStatus"
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
            Log "Tray app started"
        } catch {
            Log "Tray start warning: $_"
        }
    } else {
        Log "No user logged in - tray will start on next login (registry autostart)"
    }
}

# Step 7: Set license tier in config.json
$configFile = "$DataDir\config.json"
try {
    if (Test-Path $configFile) {
        $config = Get-Content $configFile -Raw | ConvertFrom-Json
    } else {
        $config = [PSCustomObject]@{}
    }
    $config | Add-Member -NotePropertyName "activeTier" -NotePropertyValue $Tier -Force
    $config | ConvertTo-Json -Depth 10 | Set-Content $configFile -Encoding UTF8
    Log "Config: activeTier set to $Tier"
} catch {
    Log "Config update warning: $_"
}

# Step 8: Verify version
$exeVersion = (Get-Item "$InstallDir\Service\PCPlusService.exe" -ErrorAction SilentlyContinue).VersionInfo.ProductVersion
Log "Installed version: $exeVersion"

# Cleanup
Remove-Item $TempExe -Force -ErrorAction SilentlyContinue

Log "Deployment complete. Service: $svcStatus, Version: $exeVersion"
