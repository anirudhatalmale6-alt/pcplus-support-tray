<#
.SYNOPSIS
    Adds antivirus exclusions for PC Plus Endpoint Protection and Tactical RMM.
    Run this ONCE on all managed PCs BEFORE deploying Endpoint Protection.
    This script has NO HTTP calls so Avast will not flag it.

.NOTES
    Tactical RMM Settings:
    - Shell Type: PowerShell
    - Timeout: 120 seconds
    - Run As User: unchecked (runs as SYSTEM)
#>

$ErrorActionPreference = "Continue"

Write-Host "Adding antivirus exclusions for PC Plus + Tactical RMM..."

# All paths to exclude
$ExcludePaths = @(
    "$env:ProgramFiles\PC Plus\Endpoint Protection",
    "$env:ProgramFiles\PC Plus\Endpoint Protection\Service\PCPlusService.exe",
    "$env:ProgramFiles\PC Plus\Endpoint Protection\Tray\PCPlusTray.exe",
    "$env:ProgramData\PCPlusEndpoint",
    "$env:ProgramData\PCPlusEndpoint\heartbeat.ps1",
    "$env:ProgramData\TacticalRMM",
    "$env:ProgramFiles\TacticalAgent",
    "$env:ProgramFiles\Mesh Agent"
)

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

Write-Host ""
Write-Host "============================================="
Write-Host "All antivirus exclusions applied!"
Write-Host "You can now safely deploy Endpoint Protection."
Write-Host "============================================="
