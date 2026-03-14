#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Deploys PC Plus Support Tray Utility via Tactical RMM.
.DESCRIPTION
    Downloads the latest release from GitHub, installs silently, creates config,
    sets up auto-start, and launches the utility. Designed for Tactical RMM deployment.
.NOTES
    Company: PC Plus Computing
    GitHub: anirudhatalmale6-alt/pcplus-support-tray
#>

$ErrorActionPreference = "Stop"

# ─── Configuration ───
$GitHubRepo = "anirudhatalmale6-alt/pcplus-support-tray"
$GitHubApiUrl = "https://api.github.com/repos/$GitHubRepo/releases/latest"
$InstallDir = "$env:ProgramFiles\PCPlusSupport"
$DataDir = "$env:ProgramData\PCPlusSupport"
$ExeName = "PCPlusSupportTray.exe"
$ServiceRegKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
$ServiceRegName = "PCPlusSupport"

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  PC Plus Computing - Support Tray Deployer" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# ─── Check if already installed ───
$existingExe = Join-Path $InstallDir $ExeName
if (Test-Path $existingExe) {
    $currentVer = (Get-Item $existingExe).VersionInfo.ProductVersion
    Write-Host "[INFO] Support Tray already installed. Version: $currentVer" -ForegroundColor Yellow
    Write-Host "[INFO] Will check for updates..." -ForegroundColor Yellow
}

# ─── Get latest release from GitHub ───
Write-Host "[1/5] Checking latest release..." -ForegroundColor White
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
    $headers = @{ "User-Agent" = "PCPlusSupportTray-Deployer" }
    $release = Invoke-RestMethod -Uri $GitHubApiUrl -Headers $headers -Method Get

    $latestVersion = $release.tag_name.TrimStart('v', 'V')
    Write-Host "      Latest version: v$latestVersion" -ForegroundColor Gray

    # Find zip asset
    $zipAsset = $release.assets | Where-Object { $_.name -like "*.zip" } | Select-Object -First 1
    if (-not $zipAsset) {
        Write-Host "[ERROR] No zip asset found in latest release." -ForegroundColor Red
        exit 1
    }
    $downloadUrl = $zipAsset.browser_download_url
    Write-Host "      Asset: $($zipAsset.name)" -ForegroundColor Gray
} catch {
    Write-Host "[ERROR] Failed to check GitHub releases: $_" -ForegroundColor Red
    exit 1
}

# ─── Check if update needed ───
if (Test-Path $existingExe) {
    $currentVer = (Get-Item $existingExe).VersionInfo.ProductVersion
    if ($currentVer -and $currentVer -ne "" ) {
        try {
            $current = [Version]$currentVer
            $latest = [Version]$latestVersion
            if ($latest -le $current) {
                Write-Host "[OK] Already running latest version (v$currentVer). No update needed." -ForegroundColor Green
                # Make sure it's running
                $proc = Get-Process -Name "PCPlusSupportTray" -ErrorAction SilentlyContinue
                if (-not $proc) {
                    Write-Host "[FIX] Starting utility..." -ForegroundColor Yellow
                    Start-Process -FilePath $existingExe
                }
                exit 0
            }
        } catch { }
    }
}

# ─── Download ───
Write-Host "[2/5] Downloading v$latestVersion..." -ForegroundColor White
$zipPath = Join-Path $env:TEMP "PCPlusSupportTray.zip"
$extractDir = Join-Path $env:TEMP "PCPlusSupportTray-extract"

try {
    [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    $webClient = New-Object System.Net.WebClient
    $webClient.Headers.Add("User-Agent", "PCPlusSupportTray-Deployer")
    $webClient.DownloadFile($downloadUrl, $zipPath)
    [Net.ServicePointManager]::ServerCertificateValidationCallback = $null

    $fileSize = [math]::Round((Get-Item $zipPath).Length / 1MB, 1)
    Write-Host "      Downloaded: $fileSize MB" -ForegroundColor Gray
} catch {
    Write-Host "[ERROR] Download failed: $_" -ForegroundColor Red
    exit 1
}

# ─── Stop existing process ───
$proc = Get-Process -Name "PCPlusSupportTray" -ErrorAction SilentlyContinue
if ($proc) {
    Write-Host "[3/5] Stopping existing utility..." -ForegroundColor White
    Stop-Process -Name "PCPlusSupportTray" -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
} else {
    Write-Host "[3/5] No existing process running." -ForegroundColor White
}

# ─── Extract and install ───
Write-Host "[4/5] Installing..." -ForegroundColor White
try {
    # Clean extract directory
    if (Test-Path $extractDir) { Remove-Item $extractDir -Recurse -Force }
    Expand-Archive -Path $zipPath -DestinationPath $extractDir -Force

    # Create install directory
    if (-not (Test-Path $InstallDir)) { New-Item -Path $InstallDir -ItemType Directory -Force | Out-Null }

    # Copy exe and icon
    Copy-Item -Path (Join-Path $extractDir $ExeName) -Destination $InstallDir -Force
    $iconSrc = Join-Path $extractDir "icon.ico"
    if (Test-Path $iconSrc) { Copy-Item -Path $iconSrc -Destination $InstallDir -Force }

    Write-Host "      Installed to: $InstallDir" -ForegroundColor Gray
} catch {
    Write-Host "[ERROR] Installation failed: $_" -ForegroundColor Red
    exit 1
}

# ─── Create config if not exists ───
$configFile = Join-Path $DataDir "config.json"
if (-not (Test-Path $configFile)) {
    Write-Host "      Creating default config..." -ForegroundColor Gray
    if (-not (Test-Path $DataDir)) { New-Item -Path $DataDir -ItemType Directory -Force | Out-Null }
    New-Item -Path (Join-Path $DataDir "Screenshots") -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
    New-Item -Path (Join-Path $DataDir "Tickets") -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null

    $config = @{
        CompanyName = "PC Plus Computing"
        RmmUrl = "https://rmm.pcpluscomputing.com"
        RmmApiKey = ""
        SupportPhone = "16047601662"
        SupportEmail = "pcpluscomputing@gmail.com"
        SupportChatUrl = ""
        ChatServerUrl = ""
        TicketPortalUrl = ""
        ZammadUrl = "https://support.pcpluscomputing.com"
        ZammadApiToken = "pcplus2026trayapp"
        WebsiteUrl = "https://pcpluscomputing.com"
        LiveChatUrl = "https://pcpluscomputing51.my3cx.ca/callus/#LiveChat477559"
        ForumUrl = "https://forum.pcpluscomputing.com/"
        ContactUrl = "https://pcpluscomputing.com/contact-us/"
        AppointmentUrl = "https://pcpluscomputing.com/appointments/"
        ServiceRequestUrl = "https://pos.pcpluscomputing.com/servicerequests/"
        PersistentOverlay = $false
    } | ConvertTo-Json -Depth 2

    Set-Content -Path $configFile -Value $config -Encoding UTF8
}

# ─── Set auto-start ───
$exePath = Join-Path $InstallDir $ExeName
Set-ItemProperty -Path $ServiceRegKey -Name $ServiceRegName -Value "`"$exePath`"" -Type String -Force

# ─── Create Start Menu shortcut ───
$shortcutDir = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\PC Plus Computing"
if (-not (Test-Path $shortcutDir)) { New-Item -Path $shortcutDir -ItemType Directory -Force | Out-Null }
$ws = New-Object -ComObject WScript.Shell
$shortcut = $ws.CreateShortcut("$shortcutDir\PC Plus Support.lnk")
$shortcut.TargetPath = $exePath
$shortcut.Description = "PC Plus Computing Support Utility"
$shortcut.Save()

# ─── Launch ───
Write-Host "[5/5] Starting utility..." -ForegroundColor White
Start-Process -FilePath $exePath

Start-Sleep -Seconds 2

Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "  Deployment Summary" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host "  Computer:  $env:COMPUTERNAME" -ForegroundColor White
Write-Host "  Version:   v$latestVersion" -ForegroundColor White
Write-Host "  Location:  $InstallDir" -ForegroundColor White
Write-Host "  Config:    $configFile" -ForegroundColor White
Write-Host "  Auto-Start: Yes (registry)" -ForegroundColor White
Write-Host "============================================" -ForegroundColor Green
Write-Host ""

# ─── Cleanup ───
Remove-Item -Path $zipPath -Force -ErrorAction SilentlyContinue
Remove-Item -Path $extractDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "[DONE] PC Plus Support Tray deployed successfully!" -ForegroundColor Green
exit 0
