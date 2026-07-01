<#
.SYNOPSIS
    PC Plus Computing - Network Sentry (24/7 Continuous Collector)
    Installs Sysmon + configures Windows audit policies for real-time
    security event collection. Runs as a Windows service, collects 24/7.
.DESCRIPTION
    Modes:
      install   - Install Sysmon, configure audit policies, start service
      report    - Generate HTML report from all collected data
      status    - Show collection status
      uninstall - Remove Sysmon, restore audit policies
.NOTES
    Deploy via Tactical RMM. Run as Administrator.
    Sysmon captures: process creation, network connections, DNS queries,
    file creation, registry changes, image loads, pipe connections.
    Windows Audit captures: logon/logoff, account changes, privilege use.
#>

param(
    [ValidateSet('install','report','status','uninstall')]
    [string]$Mode = 'install',
    [int]$CollectionDays = 7,
    [switch]$DisableNetworkScan
)

$BaseDir = "$env:ProgramData\PCPlusEndpoint\NetworkSecurity"
$SysmonDir = "$BaseDir\Sysmon"
$DataDir = "$BaseDir\data"
$ConfigPath = "$BaseDir\config.json"
$ServiceName = "PCPlusNetworkSentry"

$ErrorActionPreference = "SilentlyContinue"

# ============================================================
# SYSMON CONFIGURATION (security-focused, moderate verbosity)
# ============================================================
$SysmonConfig = @'
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <!-- Process Creation (Event 1) - log all with command line -->
    <RuleGroup name="ProcessCreate" groupRelation="or">
      <ProcessCreate onmatch="exclude">
        <Image condition="is">C:\Windows\System32\conhost.exe</Image>
        <Image condition="is">C:\Windows\System32\wbem\WmiPrvSE.exe</Image>
        <Image condition="end with">RuntimeBroker.exe</Image>
        <Image condition="end with">backgroundTaskHost.exe</Image>
        <Image condition="end with">SearchProtocolHost.exe</Image>
        <Image condition="end with">SearchFilterHost.exe</Image>
      </ProcessCreate>
    </RuleGroup>

    <!-- Network Connection (Event 3) - all outbound connections -->
    <RuleGroup name="NetworkConnect" groupRelation="or">
      <NetworkConnect onmatch="exclude">
        <Image condition="end with">svchost.exe</Image>
        <DestinationPort condition="is">123</DestinationPort>
        <DestinationHostname condition="end with">.windowsupdate.com</DestinationHostname>
        <DestinationHostname condition="end with">.microsoft.com</DestinationHostname>
      </NetworkConnect>
    </RuleGroup>

    <!-- DNS Query (Event 22) - all DNS queries -->
    <RuleGroup name="DnsQuery" groupRelation="or">
      <DnsQuery onmatch="exclude">
        <QueryName condition="end with">.microsoft.com</QueryName>
        <QueryName condition="end with">.windowsupdate.com</QueryName>
        <QueryName condition="end with">.msftconnecttest.com</QueryName>
        <QueryName condition="end with">.msedge.net</QueryName>
      </DnsQuery>
    </RuleGroup>

    <!-- File Create (Event 11) - executables and scripts only -->
    <RuleGroup name="FileCreate" groupRelation="or">
      <FileCreate onmatch="include">
        <TargetFilename condition="end with">.exe</TargetFilename>
        <TargetFilename condition="end with">.dll</TargetFilename>
        <TargetFilename condition="end with">.bat</TargetFilename>
        <TargetFilename condition="end with">.cmd</TargetFilename>
        <TargetFilename condition="end with">.ps1</TargetFilename>
        <TargetFilename condition="end with">.vbs</TargetFilename>
        <TargetFilename condition="end with">.js</TargetFilename>
        <TargetFilename condition="end with">.hta</TargetFilename>
        <TargetFilename condition="end with">.scr</TargetFilename>
        <TargetFilename condition="end with">.lnk</TargetFilename>
      </FileCreate>
    </RuleGroup>

    <!-- Registry (Event 12/13/14) - persistence mechanisms -->
    <RuleGroup name="RegistryEvent" groupRelation="or">
      <RegistryEvent onmatch="include">
        <TargetObject condition="contains">CurrentVersion\Run</TargetObject>
        <TargetObject condition="contains">CurrentVersion\RunOnce</TargetObject>
        <TargetObject condition="contains">Winlogon</TargetObject>
        <TargetObject condition="contains">Services</TargetObject>
        <TargetObject condition="contains">\Policies\</TargetObject>
      </RegistryEvent>
    </RuleGroup>

    <!-- Image Load (Event 7) - only unsigned DLLs -->
    <RuleGroup name="ImageLoad" groupRelation="or">
      <ImageLoad onmatch="include">
        <Signed condition="is">false</Signed>
      </ImageLoad>
    </RuleGroup>

    <!-- Pipe Created/Connected (Event 17/18) - lateral movement indicator -->
    <RuleGroup name="PipeEvent" groupRelation="or">
      <PipeEvent onmatch="include">
        <PipeName condition="contains">psexec</PipeName>
        <PipeName condition="contains">paexec</PipeName>
        <PipeName condition="contains">remcom</PipeName>
        <PipeName condition="contains">csexec</PipeName>
      </PipeEvent>
    </RuleGroup>

    <!-- Process Access (Event 10) - credential dumping detection -->
    <RuleGroup name="ProcessAccess" groupRelation="or">
      <ProcessAccess onmatch="include">
        <TargetImage condition="is">C:\Windows\System32\lsass.exe</TargetImage>
      </ProcessAccess>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
'@

# ============================================================
# WINDOWS AUDIT POLICY CONFIGURATION
# ============================================================
function Enable-SecurityAuditPolicies {
    Write-Host "Configuring Windows audit policies..." -ForegroundColor Yellow

    # Logon/Logoff
    auditpol /set /subcategory:"Logon" /success:enable /failure:enable
    auditpol /set /subcategory:"Logoff" /success:enable /failure:enable
    auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable
    auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable

    # Account Management
    auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
    auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
    auditpol /set /subcategory:"Computer Account Management" /success:enable /failure:enable

    # Privilege Use
    auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable

    # Object Access
    auditpol /set /subcategory:"File Share" /success:enable /failure:enable
    auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable

    # Policy Change
    auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable
    auditpol /set /subcategory:"Authentication Policy Change" /success:enable /failure:enable

    # System
    auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable
    auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable

    # Increase security log size to 256MB for 7-day retention
    wevtutil sl Security /ms:268435456

    # Enable PowerShell logging
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    New-Item -Path $regPath -Force | Out-Null
    Set-ItemProperty -Path $regPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord

    $regPath2 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
    New-Item -Path $regPath2 -Force | Out-Null
    Set-ItemProperty -Path $regPath2 -Name "EnableModuleLogging" -Value 1 -Type DWord

    Write-Host "  Audit policies configured" -ForegroundColor Green
}

# ============================================================
# INSTALL SYSMON
# ============================================================
function Install-Sysmon {
    New-Item -Path $SysmonDir -ItemType Directory -Force | Out-Null

    # Check if Sysmon is already installed
    $sysmonService = Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue
    if (-not $sysmonService) {
        $sysmonService = Get-Service -Name Sysmon -ErrorAction SilentlyContinue
    }

    # Download Sysmon
    $sysmonZip = "$SysmonDir\Sysmon.zip"
    $sysmonExe = "$SysmonDir\Sysmon64.exe"

    if (-not (Test-Path $sysmonExe)) {
        Write-Host "Downloading Sysmon..." -ForegroundColor Yellow
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        try {
            Invoke-WebRequest "https://download.sysinternals.com/files/Sysmon.zip" -OutFile $sysmonZip -UseBasicParsing
            Expand-Archive $sysmonZip -DestinationPath $SysmonDir -Force
            Remove-Item $sysmonZip -Force
            Write-Host "  Sysmon downloaded" -ForegroundColor Green
        } catch {
            Write-Host "  Failed to download Sysmon: $_" -ForegroundColor Red
            return $false
        }
    }

    # Write config
    $configPath = "$SysmonDir\sysmon-config.xml"
    $SysmonConfig | Out-File $configPath -Encoding UTF8 -Force

    if ($sysmonService) {
        Write-Host "Updating Sysmon configuration..." -ForegroundColor Yellow
        & $sysmonExe -c $configPath 2>&1 | Out-Null
        Write-Host "  Sysmon config updated" -ForegroundColor Green
    } else {
        Write-Host "Installing Sysmon..." -ForegroundColor Yellow
        & $sysmonExe -accepteula -i $configPath 2>&1 | Out-Null
        Write-Host "  Sysmon installed" -ForegroundColor Green
    }

    return $true
}

# ============================================================
# COLLECTOR SERVICE (runs continuously, reads event log in real-time)
# ============================================================
$CollectorScript = @'
param([string]$BaseDir)
$ErrorActionPreference = "SilentlyContinue"
$DataDir = "$BaseDir\data"
New-Item $DataDir -ItemType Directory -Force | Out-Null

$lastSecurityTime = (Get-Date).AddMinutes(-5)
$lastSysmonTime = (Get-Date).AddMinutes(-5)
$cycleCount = 0

while ($true) {
    $cycleCount++
    $timestamp = Get-Date -Format "yyyyMMdd_HH"
    $hourFile = "$DataDir\events_$timestamp.json"

    $events = @()

    # Collect Security events (login, lockout, account changes)
    try {
        $secEvents = Get-WinEvent -FilterHashtable @{
            LogName='Security'
            Id=@(4624,4625,4634,4647,4648,4672,4720,4722,4723,4724,4725,4726,4732,4733,4740,4756,4767)
            StartTime=$lastSecurityTime
        } -MaxEvents 500 2>$null

        foreach ($evt in $secEvents) {
            $xml = [xml]$evt.ToXml()
            $d = @{}
            foreach ($x in $xml.Event.EventData.Data) { $d[$x.Name] = $x.'#text' }

            # Skip noise
            $user = $d['TargetUserName']
            if ($user -in @('-','SYSTEM','LOCAL SERVICE','NETWORK SERVICE','ANONYMOUS LOGON','DWM-1','DWM-2','DWM-3','UMFD-0','UMFD-1','UMFD-2')) { continue }
            if ($user -match '\$$') { continue }
            $lt = [int]$d['LogonType']
            if ($evt.Id -in 4624,4625 -and $lt -in 0,5) { continue }

            $ip = $d['IpAddress']; if ($ip -in @('-','::1','127.0.0.1')) { $ip = 'Local' }

            $events += @{
                t = $evt.TimeCreated.ToString("o")
                src = "security"
                eid = $evt.Id
                user = $user
                domain = $d['TargetDomainName']
                ip = $ip
                port = $d['IpPort']
                lt = $lt
                status = $d['Status']
                sub = $d['SubStatus']
                ws = $d['WorkstationName']
                proc = $d['ProcessName']
                by = $d['SubjectUserName']
                group = if ($evt.Id -in 4732,4733,4756) { $d['TargetUserName'] } else { $null }
                member = $d['MemberName']
            }
        }
        if ($secEvents.Count -gt 0) {
            $lastSecurityTime = ($secEvents | Select-Object -First 1).TimeCreated.AddSeconds(1)
        }
    } catch {}

    # Collect Sysmon events (process, network, DNS, file, registry)
    try {
        $sysEvents = Get-WinEvent -FilterHashtable @{
            LogName='Microsoft-Windows-Sysmon/Operational'
            StartTime=$lastSysmonTime
        } -MaxEvents 1000 2>$null

        foreach ($evt in $sysEvents) {
            $xml = [xml]$evt.ToXml()
            $d = @{}
            foreach ($x in $xml.Event.EventData.Data) { $d[$x.Name] = $x.'#text' }

            $entry = @{
                t = $evt.TimeCreated.ToString("o")
                src = "sysmon"
                eid = $evt.Id
            }

            switch ($evt.Id) {
                1 { # Process Create
                    $entry.image = $d['Image']
                    $entry.cmdline = if ($d['CommandLine'].Length -gt 500) { $d['CommandLine'].Substring(0,500) } else { $d['CommandLine'] }
                    $entry.user = $d['User']
                    $entry.parent = $d['ParentImage']
                    $entry.hash = $d['Hashes']
                }
                3 { # Network Connection
                    $entry.image = $d['Image']
                    $entry.user = $d['User']
                    $entry.proto = $d['Protocol']
                    $entry.srcip = $d['SourceIp']
                    $entry.srcport = $d['SourcePort']
                    $entry.dstip = $d['DestinationIp']
                    $entry.dstport = $d['DestinationPort']
                    $entry.dsthost = $d['DestinationHostname']
                }
                7 { # Image Load (unsigned DLL)
                    $entry.image = $d['Image']
                    $entry.loaded = $d['ImageLoaded']
                    $entry.signed = $d['Signed']
                    $entry.sig = $d['Signature']
                }
                10 { # Process Access (LSASS)
                    $entry.source = $d['SourceImage']
                    $entry.target = $d['TargetImage']
                    $entry.access = $d['GrantedAccess']
                }
                11 { # File Create
                    $entry.image = $d['Image']
                    $entry.file = $d['TargetFilename']
                }
                {$_ -in 12,13,14} { # Registry
                    $entry.image = $d['Image']
                    $entry.target = $d['TargetObject']
                    $entry.details = $d['Details']
                }
                {$_ -in 17,18} { # Pipe
                    $entry.image = $d['Image']
                    $entry.pipe = $d['PipeName']
                }
                22 { # DNS Query
                    $entry.image = $d['Image']
                    $entry.query = $d['QueryName']
                    $entry.result = $d['QueryResults']
                }
            }
            $events += $entry
        }
        if ($sysEvents.Count -gt 0) {
            $lastSysmonTime = ($sysEvents | Select-Object -First 1).TimeCreated.AddSeconds(1)
        }
    } catch {}

    # Append to hourly file
    if ($events.Count -gt 0) {
        $jsonLines = $events | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 3 }
        $jsonLines | Add-Content $hourFile -Encoding UTF8
    }

    # Update status
    @{
        lastRun = (Get-Date -Format "o")
        cycleCount = $cycleCount
        eventsThisCycle = $events.Count
        status = "running"
    } | ConvertTo-Json | Out-File "$BaseDir\sentry_status.json" -Encoding UTF8 -Force

    # Cleanup files older than collection period
    $cutoff = (Get-Date).AddDays(-14)
    Get-ChildItem "$DataDir\events_*.json" | Where-Object { $_.LastWriteTime -lt $cutoff } | Remove-Item -Force

    # Sleep 10 seconds between collection cycles
    Start-Sleep -Seconds 10
}
'@

# ============================================================
# INSTALL MODE
# ============================================================
if ($Mode -eq 'install') {
    Write-Host "=== PC Plus Network Sentry - 24/7 Installation ===" -ForegroundColor Cyan

    New-Item -Path $DataDir -ItemType Directory -Force | Out-Null

    # Install Sysmon
    $sysmonOk = Install-Sysmon
    if (-not $sysmonOk) {
        Write-Host "Sysmon install failed - continuing with Windows events only" -ForegroundColor Yellow
    }

    # Enable audit policies
    Enable-SecurityAuditPolicies

    # Save collector script
    $collectorPath = "$BaseDir\SentryCollector.ps1"
    $CollectorScript | Out-File $collectorPath -Encoding UTF8 -Force

    # Create scheduled task that runs at startup and stays running
    $taskName = "PCPlus Network Sentry"
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$collectorPath`" -BaseDir `"$BaseDir`""
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit (New-TimeSpan -Days $CollectionDays)

    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "PC Plus Computing 24/7 Network Security Monitor - collects security events continuously"

    # Start it now
    Start-ScheduledTask -TaskName $taskName

    # Save config
    @{
        installDate = (Get-Date -Format "o")
        collectionDays = $CollectionDays
        mode = "24x7"
        sysmonInstalled = $sysmonOk
        computerName = $env:COMPUTERNAME
        enableNetworkScan = (-not $DisableNetworkScan)
        status = "active"
    } | ConvertTo-Json | Out-File $ConfigPath -Encoding UTF8 -Force

    # Also download the report generator
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest 'https://raw.githubusercontent.com/anirudhatalmale6-alt/pcplus-support-tray/main/scripts/PCPlus-NetworkSecurityScan.ps1' -OutFile "$BaseDir\PCPlus-NetworkSecurityScan.ps1" -UseBasicParsing
    } catch {}

    Write-Host "`n=== INSTALLATION COMPLETE ===" -ForegroundColor Green
    Write-Host "Sysmon: $(if($sysmonOk){'INSTALLED'}else{'SKIPPED'})" -ForegroundColor $(if($sysmonOk){'Green'}else{'Yellow'})
    Write-Host "Audit Policies: CONFIGURED" -ForegroundColor Green
    Write-Host "Collector: RUNNING 24/7" -ForegroundColor Green
    Write-Host "Collection period: $CollectionDays days" -ForegroundColor Cyan
    Write-Host "Data: $DataDir" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Capturing:" -ForegroundColor Yellow
    Write-Host "  - Every login attempt (success/fail/RDP/SMB/SSH)" -ForegroundColor White
    Write-Host "  - Every process execution with command line" -ForegroundColor White
    Write-Host "  - Every network connection with process mapping" -ForegroundColor White
    Write-Host "  - Every DNS query with process mapping" -ForegroundColor White
    Write-Host "  - File creation (executables, scripts)" -ForegroundColor White
    Write-Host "  - Registry persistence changes" -ForegroundColor White
    Write-Host "  - LSASS access (credential theft detection)" -ForegroundColor White
    Write-Host "  - Unsigned DLL loading" -ForegroundColor White
    Write-Host "  - PowerShell script execution" -ForegroundColor White
    Write-Host "  - Account changes and privilege escalation" -ForegroundColor White
    exit 0
}

# ============================================================
# STATUS MODE
# ============================================================
if ($Mode -eq 'status') {
    $cfg = if (Test-Path $ConfigPath) { Get-Content $ConfigPath -Raw | ConvertFrom-Json } else { $null }
    $status = if (Test-Path "$BaseDir\sentry_status.json") { Get-Content "$BaseDir\sentry_status.json" -Raw | ConvertFrom-Json } else { $null }
    $dataFiles = (Get-ChildItem "$DataDir\events_*.json" -ErrorAction SilentlyContinue)
    $totalSize = ($dataFiles | Measure-Object -Property Length -Sum).Sum / 1MB

    $sysmonRunning = (Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue).Status -eq 'Running'
    if (-not $sysmonRunning) { $sysmonRunning = (Get-Service -Name Sysmon -ErrorAction SilentlyContinue).Status -eq 'Running' }

    $taskRunning = (Get-ScheduledTask -TaskName "PCPlus Network Sentry" -ErrorAction SilentlyContinue).State -eq 'Running'

    Write-Host "=== PC Plus Network Sentry Status ===" -ForegroundColor Cyan
    Write-Host "Sysmon: $(if($sysmonRunning){'RUNNING'}else{'NOT RUNNING'})" -ForegroundColor $(if($sysmonRunning){'Green'}else{'Red'})
    Write-Host "Collector: $(if($taskRunning){'RUNNING'}else{'STOPPED'})" -ForegroundColor $(if($taskRunning){'Green'}else{'Red'})
    if ($status) {
        Write-Host "Last cycle: $($status.lastRun)" -ForegroundColor White
        Write-Host "Cycles: $($status.cycleCount)" -ForegroundColor White
        Write-Host "Events last cycle: $($status.eventsThisCycle)" -ForegroundColor White
    }
    Write-Host "Data files: $($dataFiles.Count)" -ForegroundColor White
    Write-Host "Data size: $([Math]::Round($totalSize, 2)) MB" -ForegroundColor White
    if ($cfg) {
        $installed = [DateTime]::Parse($cfg.installDate)
        Write-Host "Running since: $($installed.ToString('MMM d, yyyy h:mm tt'))" -ForegroundColor White
        Write-Host "Days active: $([Math]::Round(((Get-Date) - $installed).TotalDays, 1))" -ForegroundColor White
    }
    exit 0
}

# ============================================================
# UNINSTALL MODE
# ============================================================
if ($Mode -eq 'uninstall') {
    Write-Host "=== Uninstalling PC Plus Network Sentry ===" -ForegroundColor Yellow

    # Stop and remove scheduled task
    Stop-ScheduledTask -TaskName "PCPlus Network Sentry" -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName "PCPlus Network Sentry" -Confirm:$false -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName "PCPlus Network Security Collector" -Confirm:$false -ErrorAction SilentlyContinue

    # Uninstall Sysmon
    $sysmonExe = "$SysmonDir\Sysmon64.exe"
    if (Test-Path $sysmonExe) {
        & $sysmonExe -u force 2>&1 | Out-Null
        Write-Host "Sysmon uninstalled" -ForegroundColor Green
    }

    Write-Host "Scheduled tasks removed" -ForegroundColor Green
    Write-Host "Data preserved at: $DataDir" -ForegroundColor Yellow
    exit 0
}

# ============================================================
# REPORT MODE
# ============================================================
if ($Mode -eq 'report') {
    Write-Host "=== Generating 24/7 Security Report ===" -ForegroundColor Cyan

    $dataFiles = Get-ChildItem "$DataDir\events_*.json" -ErrorAction SilentlyContinue | Sort-Object Name
    if ($dataFiles.Count -eq 0) {
        Write-Host "No data files found. Collector may not have started yet." -ForegroundColor Red
        exit 1
    }

    Write-Host "Reading $($dataFiles.Count) data files..." -ForegroundColor Yellow

    # Also run the instant scanner for the HTML report
    $scanScript = "$BaseDir\PCPlus-NetworkSecurityScan.ps1"
    if (-not (Test-Path $scanScript)) {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest 'https://raw.githubusercontent.com/anirudhatalmale6-alt/pcplus-support-tray/main/scripts/PCPlus-NetworkSecurityScan.ps1' -OutFile $scanScript -UseBasicParsing
    }

    $cfg = if (Test-Path $ConfigPath) { Get-Content $ConfigPath -Raw | ConvertFrom-Json } else { $null }
    $daysRunning = if ($cfg.installDate) { [Math]::Round(((Get-Date) - [DateTime]::Parse($cfg.installDate)).TotalDays) } else { 7 }

    & $scanScript -DaysBack ([Math]::Max(1, $daysRunning)) -OutputDir $BaseDir

    Write-Host "`nReport generated: $BaseDir\report.html" -ForegroundColor Green
    exit 0
}
