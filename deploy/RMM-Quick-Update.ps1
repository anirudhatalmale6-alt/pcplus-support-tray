# PC Plus Quick Update - Simple version for RMM
# Run as System in Tactical RMM

$Version = "5.10.0"
$ExeUrl = "https://github.com/anirudhatalmale6-alt/pcplus-support-tray/releases/download/v$Version/PCPlusEndpoint-Setup-$Version.exe"
$TempExe = "C:\Windows\Temp\PCPlusEndpoint-Setup-$Version.exe"
$LogFile = "C:\ProgramData\PCPlusEndpoint\Logs\deploy.log"

function Log($msg) {
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$ts] $msg"
    Write-Host $line
    New-Item -Path (Split-Path $LogFile) -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}

# Check if already updated
$exe = "C:\Program Files\PC Plus\Endpoint Protection\Service\PCPlusService.exe"
if (Test-Path $exe) {
    $ver = (Get-Item $exe).VersionInfo.ProductVersion
    if ($ver -and $ver.StartsWith($Version)) {
        $svc = (Get-Service -Name "PCPlusEndpoint" -ErrorAction SilentlyContinue).Status
        if ($svc -eq "Running") {
            Log "Already on v$Version and running. Done."
            Write-Host "SKIP: Already on v$Version"
            exit 0
        }
    }
    Log "Current version: $ver - upgrading to $Version"
}

# Kill everything
Log "Stopping service and tray..."
Get-Process -Name "PCPlusTray" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Stop-Service -Name "PCPlusEndpoint" -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 3

# If service process still running, sc delete it
$svcPid = (Get-WmiObject Win32_Service -Filter "Name='PCPlusEndpoint'" -ErrorAction SilentlyContinue).ProcessId
if ($svcPid -and $svcPid -ne 0) {
    Log "Service still running (PID $svcPid), deleting service..."
    sc.exe delete PCPlusEndpoint 2>$null
    taskkill /F /PID $svcPid 2>$null
    Start-Sleep -Seconds 3
}

# Check if process is truly dead
$still = Get-Process -Name "PCPlusService" -ErrorAction SilentlyContinue
if ($still) {
    Log "ERROR: Service process won't die. Machine needs reboot first."
    Write-Host "REBOOT_NEEDED: Service process stuck"
    # Schedule reboot + re-run
    shutdown /r /t 60 /c "PC Plus update requires reboot" /f
    exit 1
}

# Download
Log "Downloading v$Version..."
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $curlPath = Get-Command curl.exe -ErrorAction SilentlyContinue
    if ($curlPath) {
        $result = & curl.exe --ssl-no-revoke -L -o $TempExe $ExeUrl --write-out "%{http_code}" --silent 2>&1
        Log "Download HTTP: $result"
    } else {
        (New-Object System.Net.WebClient).DownloadFile($ExeUrl, $TempExe)
    }
    $size = [math]::Round((Get-Item $TempExe).Length / 1MB, 1)
    Log "Downloaded $size MB"
    if ($size -lt 50) {
        Log "ERROR: File too small ($size MB)"
        exit 1
    }
} catch {
    Log "ERROR: Download failed - $_"
    exit 1
}

# Install
Log "Installing..."
$proc = Start-Process -FilePath $TempExe -ArgumentList "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART" -Wait -PassThru
Log "Installer exit code: $($proc.ExitCode)"

# Verify
Start-Sleep -Seconds 5
$svcStatus = (Get-Service -Name "PCPlusEndpoint" -ErrorAction SilentlyContinue).Status
if ($svcStatus -ne "Running") {
    Log "Service not running ($svcStatus). Starting..."
    Start-Service -Name "PCPlusEndpoint" -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3
    $svcStatus = (Get-Service -Name "PCPlusEndpoint" -ErrorAction SilentlyContinue).Status
}

# Set tier
$configFile = "C:\ProgramData\PCPlusEndpoint\config.json"
try {
    if (Test-Path $configFile) {
        $config = Get-Content $configFile -Raw | ConvertFrom-Json
    } else {
        $config = [PSCustomObject]@{}
    }
    $config | Add-Member -NotePropertyName "activeTier" -NotePropertyValue "Premium" -Force
    $config | ConvertTo-Json -Depth 10 | Set-Content $configFile -Encoding UTF8
} catch {}

# Cleanup
Remove-Item $TempExe -Force -ErrorAction SilentlyContinue

$finalVer = (Get-Item $exe -ErrorAction SilentlyContinue).VersionInfo.ProductVersion
Log "DONE: Service=$svcStatus, Version=$finalVer"
Write-Host "SUCCESS: v$finalVer, Service=$svcStatus"
