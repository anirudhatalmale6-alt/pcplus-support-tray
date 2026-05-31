#Requires -RunAsAdministrator
<#
  PC Plus Computing - System Performance Diagnostics
  Captures detailed system metrics with and without PC Plus components running.
  Generates a clear before/after comparison report.

  Usage:
    .\PCPlus-Diagnostics.ps1                  # Full diagnostic (captures baseline, stops PC Plus, captures again, compares)
    .\PCPlus-Diagnostics.ps1 -BaselineOnly    # Just capture current state and save baseline
    .\PCPlus-Diagnostics.ps1 -Report          # Show last saved report
#>

param(
    [switch]$BaselineOnly,
    [switch]$Report
)

$DataDir = "$env:ProgramData\PCPlusSupport\Diagnostics"
$ReportFile = "$DataDir\diagnostic-report.txt"
$BaselineFile = "$DataDir\baseline.json"

if (!(Test-Path $DataDir)) { New-Item -Path $DataDir -ItemType Directory -Force | Out-Null }

function Get-SystemMetrics {
    param([int]$SampleSeconds = 15)

    Write-Host "  Sampling system for $SampleSeconds seconds..." -ForegroundColor Gray

    $cpuSamples = @()
    $ramSamples = @()

    $cpuCounter = New-Object System.Diagnostics.PerformanceCounter("Processor", "% Processor Time", "_Total")
    $cpuCounter.NextValue() | Out-Null
    Start-Sleep -Milliseconds 500

    for ($i = 0; $i -lt $SampleSeconds; $i++) {
        $cpuSamples += $cpuCounter.NextValue()
        $os = Get-CimInstance Win32_OperatingSystem
        $ramPct = [math]::Round((($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / $os.TotalVisibleMemorySize) * 100, 1)
        $ramSamples += $ramPct
        Start-Sleep -Seconds 1
        Write-Host "." -NoNewline
    }
    Write-Host ""
    $cpuCounter.Dispose()

    $os = Get-CimInstance Win32_OperatingSystem
    $totalRamGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 1)
    $freeRamGB = [math]::Round($os.FreePhysicalMemory / 1MB, 1)

    $diskIO = Get-CimInstance Win32_PerfFormattedData_PerfDisk_PhysicalDisk | Where-Object { $_.Name -eq "_Total" }

    $bootTime = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
    $uptimeMin = [math]::Round(((Get-Date) - $bootTime).TotalMinutes, 0)

    $processes = Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 10

    $pcplusProcs = Get-Process | Where-Object {
        $_.ProcessName -match "PCPlus|PCPlusSupport|PCPlusEndpoint|PCPlusTray"
    }

    $wmiProviderHost = Get-Process -Name "WmiPrvSE" -ErrorAction SilentlyContinue

    $handleCount = (Get-Process | Measure-Object HandleCount -Sum).Sum
    $threadCount = (Get-Process | Measure-Object Threads -Sum -ErrorAction SilentlyContinue).Sum
    $processCount = (Get-Process).Count

    $startupApps = Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location

    return @{
        Timestamp       = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        CpuAvg          = [math]::Round(($cpuSamples | Measure-Object -Average).Average, 1)
        CpuMax          = [math]::Round(($cpuSamples | Measure-Object -Maximum).Maximum, 1)
        CpuMin          = [math]::Round(($cpuSamples | Measure-Object -Minimum).Minimum, 1)
        RamAvg          = [math]::Round(($ramSamples | Measure-Object -Average).Average, 1)
        RamTotalGB      = $totalRamGB
        RamFreeGB       = $freeRamGB
        DiskReadsPerSec = if ($diskIO) { $diskIO.DiskReadsPerSec } else { 0 }
        DiskWritesPerSec = if ($diskIO) { $diskIO.DiskWritesPerSec } else { 0 }
        DiskQueueLen    = if ($diskIO) { $diskIO.CurrentDiskQueueLength } else { 0 }
        UptimeMinutes   = $uptimeMin
        ProcessCount    = $processCount
        HandleCount     = $handleCount
        TopProcesses    = $processes | ForEach-Object {
            @{
                Name      = $_.ProcessName
                PID       = $_.Id
                MemoryMB  = [math]::Round($_.WorkingSet64 / 1MB, 1)
                CPU_s     = [math]::Round($_.CPU, 1)
                Handles   = $_.HandleCount
            }
        }
        PCPlusProcesses = $pcplusProcs | ForEach-Object {
            @{
                Name      = $_.ProcessName
                PID       = $_.Id
                MemoryMB  = [math]::Round($_.WorkingSet64 / 1MB, 1)
                CPU_s     = [math]::Round($_.CPU, 1)
                Handles   = $_.HandleCount
                Threads   = $_.Threads.Count
            }
        }
        WmiHostMemMB    = if ($wmiProviderHost) {
            [math]::Round(($wmiProviderHost | Measure-Object WorkingSet64 -Sum).Sum / 1MB, 1)
        } else { 0 }
        WmiHostCount    = if ($wmiProviderHost) { $wmiProviderHost.Count } else { 0 }
        StartupApps     = $startupApps
    }
}

function Format-Metrics {
    param($m, [string]$Label)

    $lines = @()
    $lines += ""
    $lines += "=" * 60
    $lines += "  $Label"
    $lines += "  Captured: $($m.Timestamp)"
    $lines += "=" * 60
    $lines += ""
    $lines += "  CPU Usage:    Avg $($m.CpuAvg)%  |  Min $($m.CpuMin)%  |  Max $($m.CpuMax)%"
    $lines += "  RAM Usage:    $($m.RamAvg)% of $($m.RamTotalGB) GB  ($($m.RamFreeGB) GB free)"
    $lines += "  Disk I/O:     $($m.DiskReadsPerSec) reads/s, $($m.DiskWritesPerSec) writes/s  (queue: $($m.DiskQueueLen))"
    $lines += "  Processes:    $($m.ProcessCount) running  |  Handles: $($m.HandleCount)"
    $lines += "  WMI Hosts:    $($m.WmiHostCount) instances using $($m.WmiHostMemMB) MB"
    $lines += "  Uptime:       $($m.UptimeMinutes) minutes"
    $lines += ""
    $lines += "  --- Top 10 Processes by Memory ---"
    $lines += "  {0,-25} {1,8} {2,8} {3,8}" -f "Process", "Mem(MB)", "CPU(s)", "Handles"
    $lines += "  " + "-" * 55
    foreach ($p in $m.TopProcesses) {
        $lines += "  {0,-25} {1,8} {2,8} {3,8}" -f $p.Name, $p.MemoryMB, $p.CPU_s, $p.Handles
    }

    if ($m.PCPlusProcesses -and $m.PCPlusProcesses.Count -gt 0) {
        $lines += ""
        $lines += "  --- PC Plus Processes ---"
        $lines += "  {0,-25} {1,8} {2,8} {3,8} {4,8}" -f "Process", "Mem(MB)", "CPU(s)", "Handles", "Threads"
        $lines += "  " + "-" * 65
        $totalMem = 0; $totalCpu = 0; $totalHandles = 0; $totalThreads = 0
        foreach ($p in $m.PCPlusProcesses) {
            $lines += "  {0,-25} {1,8} {2,8} {3,8} {4,8}" -f $p.Name, $p.MemoryMB, $p.CPU_s, $p.Handles, $p.Threads
            $totalMem += $p.MemoryMB; $totalCpu += $p.CPU_s; $totalHandles += $p.Handles; $totalThreads += $p.Threads
        }
        $lines += "  " + "-" * 65
        $lines += "  {0,-25} {1,8} {2,8} {3,8} {4,8}" -f "TOTAL", [math]::Round($totalMem,1), [math]::Round($totalCpu,1), $totalHandles, $totalThreads
    } else {
        $lines += ""
        $lines += "  PC Plus components: NOT RUNNING"
    }

    return $lines
}

function Stop-PCPlusComponents {
    Write-Host "  Stopping PC Plus components..." -ForegroundColor Yellow
    Stop-Service -Name "PCPlusEndpoint" -Force -ErrorAction SilentlyContinue
    Stop-Process -Name "PCPlusTray" -Force -ErrorAction SilentlyContinue
    Stop-Process -Name "PCPlusSupportTray" -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3

    $still = Get-Process | Where-Object { $_.ProcessName -match "PCPlus" }
    if ($still) {
        $still | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    }
    Write-Host "  PC Plus components stopped." -ForegroundColor Green
}

function Start-PCPlusComponents {
    Write-Host "  Restarting PC Plus components..." -ForegroundColor Yellow
    Start-Service -Name "PCPlusEndpoint" -ErrorAction SilentlyContinue
    $trayPath = "${env:ProgramFiles}\PC Plus\Endpoint Protection\Tray\PCPlusTray.exe"
    if (Test-Path $trayPath) {
        Start-Process $trayPath -ErrorAction SilentlyContinue
    }
    $legacyPath = "${env:ProgramFiles}\PCPlusSupport\PCPlusSupportTray.exe"
    if (Test-Path $legacyPath) {
        Start-Process $legacyPath -ErrorAction SilentlyContinue
    }
    Start-Sleep -Seconds 5
    Write-Host "  PC Plus components restarted." -ForegroundColor Green
}

# ---- Main ----

$header = @"

  ============================================================
    PC Plus Computing - System Performance Diagnostics
    $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
  ============================================================

  Computer:  $env:COMPUTERNAME
  OS:        $((Get-CimInstance Win32_OperatingSystem).Caption)
  CPU:       $((Get-CimInstance Win32_Processor).Name)
  RAM:       $([math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 1)) GB
  Disk:      $((Get-CimInstance Win32_DiskDrive | Select-Object -First 1).Model)

"@

if ($Report) {
    if (Test-Path $ReportFile) {
        Get-Content $ReportFile
    } else {
        Write-Host "No diagnostic report found. Run the diagnostic first." -ForegroundColor Red
    }
    return
}

Write-Host $header -ForegroundColor Cyan

if ($BaselineOnly) {
    Write-Host "[1/1] Capturing system baseline..." -ForegroundColor Cyan
    $baseline = Get-SystemMetrics -SampleSeconds 20
    $baseline | ConvertTo-Json -Depth 5 | Set-Content $BaselineFile -Force

    $report = @($header)
    $report += Format-Metrics $baseline "BASELINE SNAPSHOT"
    $report | Set-Content $ReportFile -Force

    Write-Host ""
    Write-Host "Baseline saved to: $BaselineFile" -ForegroundColor Green
    Write-Host "Report saved to:   $ReportFile" -ForegroundColor Green
    $report | ForEach-Object { Write-Host $_ }
    return
}

# Full diagnostic: with PC Plus -> without -> comparison
Write-Host "[1/3] Capturing metrics WITH PC Plus running..." -ForegroundColor Cyan
$withPCPlus = Get-SystemMetrics -SampleSeconds 20

Write-Host ""
Write-Host "[2/3] Stopping PC Plus and capturing metrics WITHOUT it..." -ForegroundColor Cyan
Stop-PCPlusComponents
Start-Sleep -Seconds 5
$withoutPCPlus = Get-SystemMetrics -SampleSeconds 20

Write-Host ""
Write-Host "[3/3] Generating comparison report..." -ForegroundColor Cyan

Start-PCPlusComponents

$cpuDiff = [math]::Round($withPCPlus.CpuAvg - $withoutPCPlus.CpuAvg, 1)
$ramDiff = [math]::Round($withPCPlus.RamAvg - $withoutPCPlus.RamAvg, 1)
$handleDiff = $withPCPlus.HandleCount - $withoutPCPlus.HandleCount
$procDiff = $withPCPlus.ProcessCount - $withoutPCPlus.ProcessCount

$pcplusMem = 0
if ($withPCPlus.PCPlusProcesses) {
    foreach ($p in $withPCPlus.PCPlusProcesses) { $pcplusMem += $p.MemoryMB }
}

$report = @($header)
$report += Format-Metrics $withPCPlus "PHASE 1: WITH PC PLUS RUNNING"
$report += Format-Metrics $withoutPCPlus "PHASE 2: WITHOUT PC PLUS (stopped)"
$report += ""
$report += "=" * 60
$report += "  IMPACT ANALYSIS"
$report += "=" * 60
$report += ""
$report += "  CPU Impact:       $cpuDiff% average increase"
$report += "  RAM Impact:       $ramDiff% increase ($([math]::Round($pcplusMem,0)) MB direct usage)"
$report += "  Handle Impact:    $handleDiff additional handles"
$report += "  Process Impact:   $procDiff additional processes"
$report += "  WMI Host Impact:  $($withPCPlus.WmiHostMemMB) MB -> $($withoutPCPlus.WmiHostMemMB) MB"
$report += ""

if ($cpuDiff -gt 10) {
    $report += "  [!] SIGNIFICANT CPU impact detected. Health monitor polling may be too aggressive."
    $report += "      Recommendation: Increase HealthPollIntervalMs to 15000-30000 in config.json"
} elseif ($cpuDiff -gt 5) {
    $report += "  [*] MODERATE CPU impact. Consider increasing poll interval on low-spec machines."
} else {
    $report += "  [OK] CPU impact is minimal."
}

if ($pcplusMem -gt 200) {
    $report += "  [!] SIGNIFICANT memory usage ($([math]::Round($pcplusMem,0)) MB). Check for memory leaks."
} elseif ($pcplusMem -gt 100) {
    $report += "  [*] MODERATE memory usage ($([math]::Round($pcplusMem,0)) MB). Normal for endpoint protection."
} else {
    $report += "  [OK] Memory usage is low ($([math]::Round($pcplusMem,0)) MB)."
}

if ($withPCPlus.WmiHostMemMB - $withoutPCPlus.WmiHostMemMB -gt 50) {
    $report += "  [!] WMI overhead is high. Health monitor WMI queries are consuming resources."
    $report += "      Recommendation: Disable temperature monitoring on this machine."
}

$report += ""
$report += "-" * 60
$report += "  Report generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$report += "  Saved to: $ReportFile"
$report += "-" * 60

$report | Set-Content $ReportFile -Force

Write-Host ""
Write-Host "=" * 60 -ForegroundColor Cyan
$report | ForEach-Object { Write-Host $_ }

Write-Host ""
Write-Host "Full report saved to: $ReportFile" -ForegroundColor Green
Write-Host "Send this file to PC Plus Computing for analysis." -ForegroundColor Gray
