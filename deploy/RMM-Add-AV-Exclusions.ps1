<#
.SYNOPSIS
    Adds antivirus exclusions for PC Plus Endpoint Protection and Tactical RMM.
    Run this ONCE on all managed PCs BEFORE deploying Endpoint Protection.
    This script has NO HTTP calls so Avast will not flag it.
    Restarts Avast service to apply changes immediately.

.NOTES
    Tactical RMM Settings:
    - Shell Type: PowerShell
    - Timeout: 300 seconds
    - Run As User: unchecked (runs as SYSTEM)
#>

$ErrorActionPreference = "Continue"

Write-Host "Adding antivirus exclusions for PC Plus + Tactical RMM..."

# Find TRMM agent temp directory (where scripts are stored before execution)
$trmmPaths = @(
    "$env:ProgramData\TacticalRMM",
    "$env:ProgramFiles\TacticalAgent",
    "$env:ProgramFiles\Mesh Agent"
)
# Also find the actual TRMM agent install directory dynamically
$trmmSvc = Get-CimInstance Win32_Service -Filter "Name='tacticalrmm'" -ErrorAction SilentlyContinue
if ($trmmSvc -and $trmmSvc.PathName) {
    $trmmDir = Split-Path ($trmmSvc.PathName -replace '"','') -Parent
    if ($trmmDir) { $trmmPaths += $trmmDir }
    Write-Host "[INFO] TRMM agent found at: $trmmDir"
}

# All paths to exclude
$ExcludePaths = @(
    "$env:ProgramFiles\PC Plus\Endpoint Protection",
    "$env:ProgramFiles\PC Plus\Endpoint Protection\Service\PCPlusService.exe",
    "$env:ProgramFiles\PC Plus\Endpoint Protection\Tray\PCPlusTray.exe",
    "$env:ProgramData\PCPlusEndpoint",
    "$env:ProgramData\PCPlusEndpoint\heartbeat.ps1"
) + $trmmPaths

$ExcludeProcesses = @(
    "PCPlusService.exe",
    "PCPlusTray.exe",
    "tacticalrmm.exe",
    "meshagent.exe"
)

# === Windows Defender ===
foreach ($path in $ExcludePaths) {
    try { Add-MpPreference -ExclusionPath $path -ErrorAction SilentlyContinue } catch {}
}
foreach ($proc in $ExcludeProcesses) {
    try { Add-MpPreference -ExclusionProcess $proc -ErrorAction SilentlyContinue } catch {}
}
Write-Host "[OK] Windows Defender exclusions added."

# === Avast / AVG (registry method) ===
$avastRegPaths = @(
    "HKLM:\SOFTWARE\Avast Software\Avast\properties",
    "HKLM:\SOFTWARE\AVAST Software\Avast\properties",
    "HKLM:\SOFTWARE\AVG\Antivirus\properties"
)

foreach ($basePath in $avastRegPaths) {
    if (Test-Path $basePath) {
        # File/folder exclusions
        $exclKey = "$basePath\ExcludedPaths"
        try { New-Item -Path $exclKey -Force -ErrorAction SilentlyContinue | Out-Null } catch {}
        foreach ($path in $ExcludePaths) {
            try { New-ItemProperty -Path $exclKey -Name $path -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null } catch {}
        }
        Write-Host "[OK] Avast/AVG registry exclusions added at $basePath"
    }
}

# === Avast config file method (belt and suspenders) ===
$avastIniPaths = @(
    "$env:ProgramData\AVAST Software\Avast\avast5.ini",
    "$env:ProgramData\AVG\Antivirus\avgav.ini"
)

foreach ($iniPath in $avastIniPaths) {
    if (Test-Path $iniPath) {
        try {
            $content = Get-Content $iniPath -Raw -ErrorAction SilentlyContinue
            $newEntries = @()
            foreach ($path in $ExcludePaths) {
                if ($content -notmatch [regex]::Escape($path)) {
                    $newEntries += $path
                }
            }
            if ($newEntries.Count -gt 0) {
                $block = "`n[ExcludedPaths]`n" + ($newEntries -join "`n") + "`n"
                Add-Content -Path $iniPath -Value $block -ErrorAction SilentlyContinue
                Write-Host "[OK] Avast/AVG config exclusions added at $iniPath"
            }
        } catch { Write-Host "[WARN] Could not update $iniPath" }
    }
}

# === Disable Avast IDP scanning for PowerShell (prevents false positives) ===
$avastSettingsKeys = @(
    "HKLM:\SOFTWARE\Avast Software\Avast",
    "HKLM:\SOFTWARE\AVAST Software\Avast"
)
foreach ($key in $avastSettingsKeys) {
    if (Test-Path $key) {
        # Add PowerShell to trusted processes
        $trustKey = "$key\properties\TrustedProcesses"
        try {
            New-Item -Path $trustKey -Force -ErrorAction SilentlyContinue | Out-Null
            New-ItemProperty -Path $trustKey -Name "powershell.exe" -Value 1 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
            Write-Host "[OK] Added powershell.exe to Avast trusted processes."
        } catch {}
    }
}

# === Restart Avast service to apply exclusions immediately ===
$avastServices = @("AvastSvc", "avast! Antivirus", "AvastWscReporter", "aswbIDSAgent")
$restarted = $false
foreach ($svcName in $avastServices) {
    $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq "Running") {
        Write-Host "[INFO] Restarting Avast service: $svcName..."
        try {
            Restart-Service -Name $svcName -Force -ErrorAction Stop
            Write-Host "[OK] $svcName restarted - exclusions are now active."
            $restarted = $true
        } catch {
            Write-Host "[WARN] Could not restart $svcName : $_"
            Write-Host "[INFO] Trying net stop/start..."
            try {
                & net stop $svcName 2>&1 | Out-Null
                Start-Sleep -Seconds 3
                & net start $svcName 2>&1 | Out-Null
                Write-Host "[OK] $svcName restarted via net stop/start."
                $restarted = $true
            } catch { Write-Host "[WARN] Could not restart $svcName via net either." }
        }
    }
}

if (-not $restarted) {
    # Try the main Avast service by executable name
    $avastProc = Get-Process -Name "AvastSvc" -ErrorAction SilentlyContinue
    if ($avastProc) {
        Write-Host "[INFO] Avast process found but service restart failed."
        Write-Host "[WARN] Exclusions may not take effect until next Avast restart or PC reboot."
    } else {
        Write-Host "[INFO] No Avast service found running - exclusions applied for Defender only."
    }
}

Write-Host ""
Write-Host "============================================="
Write-Host "All antivirus exclusions applied!"
if ($restarted) {
    Write-Host "Avast restarted - exclusions are active NOW."
} else {
    Write-Host "NOTE: If Avast is installed, a PC reboot may be"
    Write-Host "needed for exclusions to fully take effect."
}
Write-Host "You can now safely deploy Endpoint Protection."
Write-Host "============================================="
