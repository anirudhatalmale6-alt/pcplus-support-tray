#Requires -RunAsAdministrator
<#
.SYNOPSIS
    PC Plus Endpoint Protection - One-Click Install/Update Script
    Push via Tactical RMM, PDQ Deploy, GPO, or run manually.

.PARAMETER CustomerName
    Customer display name for the dashboard.

.PARAMETER DashboardUrl
    URL of the central dashboard.

.PARAMETER CustomerId
    Customer identifier for grouping in the dashboard.

.PARAMETER PolicyProfile
    Policy profile to apply: default, high-security, home-user

.PARAMETER LicenseKey
    License key for Premium/Standard features.

.PARAMETER GitHubRepo
    GitHub repository for downloading releases.

.PARAMETER Uninstall
    Remove PC Plus Endpoint Protection completely.

.EXAMPLE
    .\Install-PCPlusEndpoint.ps1 -CustomerName "Acme Corp"
#>

param(
    [string]$DashboardUrl = "https://dashboard.pcpluscomputing.com",
    [string]$CustomerId = "",
    [string]$CustomerName = "",
    [string]$PolicyProfile = "default",
    [string]$LicenseKey = "",
    [string]$GitHubRepo = "anirudhatalmale6-alt/pcplus-support-tray",
    [switch]$Uninstall
)

$ServiceName = "PCPlusEndpoint"
$TrayAppName = "PCPlusTray"
$InstallDir = "$env:ProgramFiles\PC Plus\Endpoint Protection"
$ConfigDir = "$env:ProgramData\PCPlusEndpoint"
$LogFile = "$ConfigDir\Logs\install.log"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$timestamp] [$Level] $Message"
    if ($Level -eq "ERROR") { Write-Host $line -ForegroundColor Red }
    elseif ($Level -eq "WARN") { Write-Host $line -ForegroundColor Yellow }
    else { Write-Host $line -ForegroundColor Green }
    try { Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue } catch { }
}

function Get-LatestRelease {
    Write-Log "Checking for latest release from GitHub..."
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$GitHubRepo/releases/latest" -UseBasicParsing
        Write-Log "Found release: $($release.tag_name)"
        return $release
    }
    catch {
        Write-Log "No releases found: $_" "WARN"
        return $null
    }
}

function Install-Endpoint {
    Write-Log "=================================================="
    Write-Log "PC Plus Endpoint Protection - Installer"
    Write-Log "=================================================="

    # Create directories
    Write-Log "Creating directories..."
    @($InstallDir, "$InstallDir\Service", "$InstallDir\Tray", $ConfigDir, "$ConfigDir\Logs", "$ConfigDir\Audits") | ForEach-Object {
        New-Item -Path $_ -ItemType Directory -Force | Out-Null
    }

    # Stop existing service if running
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc) {
        Write-Log "Stopping existing service..."
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
        # Delete old service registration
        Write-Log "Removing old service registration..."
        sc.exe delete $ServiceName 2>$null | Out-Null
        Start-Sleep -Seconds 2
    }

    # Stop existing tray app
    Get-Process -Name "PCPlusTray" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

    # Download binaries
    $release = Get-LatestRelease
    if (-not $release) {
        Write-Log "Cannot download - no release found on GitHub." "ERROR"
        return $false
    }

    $installerAsset = $release.assets | Where-Object { $_.name -like "*Installer*" } | Select-Object -First 1
    if (-not $installerAsset) {
        Write-Log "No installer package found in release $($release.tag_name)." "ERROR"
        return $false
    }

    Write-Log "Downloading: $($installerAsset.name) ($([math]::Round($installerAsset.size / 1MB, 1)) MB)..."
    $zipPath = "$env:TEMP\pcplus-installer.zip"
    $extractPath = "$env:TEMP\pcplus-extract"

    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $installerAsset.browser_download_url -OutFile $zipPath -UseBasicParsing
    }
    catch {
        Write-Log "Download failed: $_" "ERROR"
        return $false
    }

    Write-Log "Extracting..."
    if (Test-Path $extractPath) { Remove-Item $extractPath -Recurse -Force }
    Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force
    Remove-Item $zipPath -Force

    # Stop processes again right before copying (they may have restarted during download)
    Write-Log "Ensuring processes are stopped before file copy..."
    # Use taskkill for lower-level process termination
    taskkill /F /IM PCPlusService.exe /T 2>$null
    taskkill /F /IM PCPlusTray.exe /T 2>$null
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc) {
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        sc.exe delete $ServiceName 2>$null | Out-Null
    }
    Start-Sleep -Seconds 3

    # Helper: copy files, renaming locked ones out of the way first
    function Copy-WithRetry {
        param([string]$Source, [string]$Dest)
        Get-ChildItem -Path $Source -Recurse | ForEach-Object {
            $relPath = $_.FullName.Substring($Source.Length).TrimStart('\')
            $target = Join-Path $Dest $relPath
            if ($_.PSIsContainer) {
                New-Item -Path $target -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
            } else {
                $targetDir = Split-Path $target -Parent
                if (-not (Test-Path $targetDir)) {
                    New-Item -Path $targetDir -ItemType Directory -Force | Out-Null
                }
                try {
                    Copy-Item -Path $_.FullName -Destination $target -Force -ErrorAction Stop
                } catch {
                    # File is locked - rename the old file out of the way
                    Write-Log "File locked: $target - renaming old file..."
                    $oldFile = "$target.old_$(Get-Date -Format 'yyyyMMddHHmmss')"
                    try {
                        [System.IO.File]::Move($target, $oldFile)
                        Write-Log "Renamed to $oldFile"
                        Copy-Item -Path $_.FullName -Destination $target -Force -ErrorAction Stop
                    } catch {
                        # Even rename failed - schedule replacement on reboot
                        Write-Log "Cannot rename - scheduling replacement on reboot..."
                        $signature = @'
[DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
public static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, int dwFlags);
'@
                        $type = Add-Type -MemberDefinition $signature -Name "WinAPI" -Namespace "MoveFile" -PassThru -ErrorAction SilentlyContinue
                        # MOVEFILE_DELAY_UNTIL_REBOOT = 0x4, MOVEFILE_REPLACE_EXISTING = 0x1
                        $type::MoveFileEx($_.FullName, $target, 0x5) | Out-Null
                        Write-Log "Scheduled: $target will be replaced on next reboot."
                        $script:needsReboot = $true
                    }
                }
            }
        }
    }

    $script:needsReboot = $false

    # Copy Service binaries
    $svcSource = Get-ChildItem -Path $extractPath -Filter "PCPlusService.exe" -Recurse | Select-Object -First 1
    if ($svcSource) {
        Write-Log "Installing service binaries..."
        Copy-WithRetry -Source $svcSource.DirectoryName -Dest "$InstallDir\Service"
    } else {
        Write-Log "PCPlusService.exe not found in package!" "ERROR"
        return $false
    }

    # Copy Tray binaries
    $traySource = Get-ChildItem -Path $extractPath -Filter "PCPlusTray.exe" -Recurse | Select-Object -First 1
    if ($traySource) {
        Write-Log "Installing tray app binaries..."
        Copy-WithRetry -Source $traySource.DirectoryName -Dest "$InstallDir\Tray"
    }

    Remove-Item $extractPath -Recurse -Force -ErrorAction SilentlyContinue

    # Write config
    Write-Config

    # Register and start Windows Service
    $serviceExe = "$InstallDir\Service\PCPlusService.exe"
    if (-not (Test-Path $serviceExe)) {
        Write-Log "Service binary not found at $serviceExe" "ERROR"
        return $false
    }

    Write-Log "Registering Windows Service..."
    try {
        New-Service -Name $ServiceName `
            -BinaryPathName "`"$serviceExe`"" `
            -DisplayName "PC Plus Endpoint Protection" `
            -Description "PC Plus Endpoint Protection - Security monitoring, ransomware defense, and system health." `
            -StartupType Automatic `
            -ErrorAction Stop | Out-Null
        Write-Log "Service registered."
    }
    catch {
        Write-Log "New-Service failed: $_ - Trying sc.exe..." "WARN"
        $scResult = sc.exe create $ServiceName binPath= "`"$serviceExe`"" start= auto DisplayName= "PC Plus Endpoint Protection" 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Log "sc.exe create also failed: $scResult" "ERROR"
            Write-Log "You can start it manually: & `"$serviceExe`"" "WARN"
            return $false
        }
        Write-Log "Service registered via sc.exe."
    }

    # Set auto-restart on failure
    sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/30000 2>$null | Out-Null

    # Start the service
    Write-Log "Starting service..."
    try {
        Start-Service -Name $ServiceName -ErrorAction Stop
        Start-Sleep -Seconds 2
        $svcStatus = (Get-Service -Name $ServiceName).Status
        Write-Log "Service status: $svcStatus"
    }
    catch {
        Write-Log "Start-Service failed: $_" "WARN"
        Write-Log "Trying net start..." "WARN"
        $netResult = net start $ServiceName 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Log "Service failed to start. Trying direct exe..." "WARN"
            # Try running the exe directly as a last resort
            Start-Process -FilePath $serviceExe -WindowStyle Hidden
            Start-Sleep -Seconds 3
            $proc = Get-Process -Name "PCPlusService" -ErrorAction SilentlyContinue
            if ($proc) {
                Write-Log "Service running as process (PID: $($proc.Id)). Will register properly on next reboot."
            } else {
                Write-Log "Could not start service. Check Windows Event Viewer for details." "ERROR"
            }
        } else {
            Write-Log "Service started via net start."
        }
    }

    # Set up Tray App auto-start
    $trayExe = "$InstallDir\Tray\PCPlusTray.exe"
    if (Test-Path $trayExe) {
        Write-Log "Configuring tray app auto-start..."
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        Set-ItemProperty -Path $regPath -Name "PCPlusEndpoint" -Value "`"$trayExe`"" -ErrorAction SilentlyContinue

        # Start the tray app
        Start-Process -FilePath $trayExe -WindowStyle Hidden -ErrorAction SilentlyContinue
        Write-Log "Tray app started."
    }

    # Create uninstall entry in Add/Remove Programs
    $uninstallKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\PCPlusEndpoint"
    New-Item -Path $uninstallKey -Force | Out-Null
    Set-ItemProperty -Path $uninstallKey -Name "DisplayName" -Value "PC Plus Endpoint Protection"
    Set-ItemProperty -Path $uninstallKey -Name "DisplayVersion" -Value "$($release.tag_name)"
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

    if ($script:needsReboot) {
        Write-Log "=================================================="
        Write-Log "REBOOT REQUIRED to complete installation!"
        Write-Log "Some files were locked and will be replaced on restart."
        Write-Log "=================================================="
    } else {
        Write-Log "=================================================="
        Write-Log "Installation complete!"
        Write-Log "=================================================="
    }
    Write-Log "Install dir: $InstallDir"
    Write-Log "Config dir: $ConfigDir"
    Write-Log "Dashboard: $DashboardUrl"
    return $true
}

function Write-Config {
    $configFile = "$ConfigDir\config.json"

    $config = @{}
    if (Test-Path $configFile) {
        try {
            $existing = Get-Content $configFile -Raw | ConvertFrom-Json
            $existing.PSObject.Properties | ForEach-Object { $config[$_.Name] = $_.Value }
        }
        catch { }
    }

    if ($DashboardUrl) { $config["dashboardApiUrl"] = $DashboardUrl }
    if ($CustomerId) { $config["customerId"] = $CustomerId }
    if ($CustomerName) { $config["companyName"] = $CustomerName }
    if ($PolicyProfile) { $config["policyProfile"] = $PolicyProfile }
    if ($LicenseKey) { $config["licenseKey"] = $LicenseKey }

    # Defaults
    if (-not $config.ContainsKey("ransomwareProtectionEnabled")) { $config["ransomwareProtectionEnabled"] = "true" }
    if (-not $config.ContainsKey("autoContainmentEnabled")) { $config["autoContainmentEnabled"] = "true" }
    if (-not $config.ContainsKey("showBalloonAlerts")) { $config["showBalloonAlerts"] = "true" }
    if (-not $config.ContainsKey("logAlerts")) { $config["logAlerts"] = "true" }

    $config | ConvertTo-Json -Depth 10 | Set-Content -Path $configFile -Encoding UTF8
    Write-Log "Config written to $configFile"
}

function Uninstall-Endpoint {
    Write-Log "Uninstalling PC Plus Endpoint Protection..."
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    sc.exe delete $ServiceName 2>$null
    Get-Process -Name "PCPlusTray" -ErrorAction SilentlyContinue | Stop-Process -Force
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "PCPlusEndpoint" -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\PCPlusEndpoint" -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Log "Uninstall complete. Config preserved at $ConfigDir"
}

# --- Main ---
# Ensure log directory exists first
New-Item -Path "$ConfigDir\Logs" -ItemType Directory -Force | Out-Null

if ($Uninstall) {
    Uninstall-Endpoint
}
else {
    $result = Install-Endpoint
    if ($result) {
        Write-Host ""
        Write-Host "SUCCESS - PC Plus Endpoint Protection is installed and running!" -ForegroundColor Cyan
        Write-Host "Dashboard: $DashboardUrl" -ForegroundColor Cyan
        Write-Host ""
    } else {
        Write-Host ""
        Write-Host "Installation had issues - check the log above for details." -ForegroundColor Yellow
        Write-Host "Log file: $LogFile" -ForegroundColor Yellow
        Write-Host ""
    }
}
