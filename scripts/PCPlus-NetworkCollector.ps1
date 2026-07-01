<#
.SYNOPSIS
    PC Plus Computing - Network Security Collector
    Persistent data collector that runs for 7-14 days, building up a
    comprehensive security assessment. Deploy via RMM.
.DESCRIPTION
    Modes:
      install   - Create scheduled task + config, start collecting
      collect   - Run one collection cycle (called by scheduled task)
      report    - Generate HTML report from all collected data
      status    - Show collection status
      uninstall - Remove scheduled task + data

    Config: C:\ProgramData\PCPlusEndpoint\NetworkSecurity\config.json
    Data:   C:\ProgramData\PCPlusEndpoint\NetworkSecurity\data\
    Report: C:\ProgramData\PCPlusEndpoint\NetworkSecurity\report.html
.EXAMPLE
    .\PCPlus-NetworkCollector.ps1 -Mode install
    .\PCPlus-NetworkCollector.ps1 -Mode install -DisableNetworkScan
    .\PCPlus-NetworkCollector.ps1 -Mode collect
    .\PCPlus-NetworkCollector.ps1 -Mode report
    .\PCPlus-NetworkCollector.ps1 -Mode uninstall
#>

param(
    [ValidateSet('install','collect','report','status','uninstall')]
    [string]$Mode = 'collect',
    [switch]$DisableNetworkScan,
    [int]$CollectionDays = 14,
    [int]$IntervalMinutes = 30
)

$BaseDir = "$env:ProgramData\PCPlusEndpoint\NetworkSecurity"
$DataDir = "$BaseDir\data"
$ConfigPath = "$BaseDir\config.json"
$TaskName = "PCPlus Network Security Collector"

# ============================================================
# CONFIG MANAGEMENT
# ============================================================
function Get-CollectorConfig {
    if (Test-Path $ConfigPath) {
        return Get-Content $ConfigPath -Raw | ConvertFrom-Json
    }
    return $null
}

function Save-CollectorConfig($cfg) {
    $cfg | ConvertTo-Json -Depth 3 | Out-File $ConfigPath -Encoding UTF8 -Force
}

# ============================================================
# INSTALL MODE
# ============================================================
if ($Mode -eq 'install') {
    New-Item -Path $DataDir -ItemType Directory -Force | Out-Null

    $config = @{
        installDate      = (Get-Date -Format "o")
        collectionDays   = $CollectionDays
        intervalMinutes  = $IntervalMinutes
        computerName     = $env:COMPUTERNAME
        enableNetworkScan = (-not $DisableNetworkScan)
        enableLoginEvents = $true
        enablePortScan    = $true
        enablePowerShell  = $true
        enableDefender    = $true
        enableDeviceDiscovery = (-not $DisableNetworkScan)
        enableServiceDetection = (-not $DisableNetworkScan)
        enableConnectionTracking = $true
        enableDnsMonitoring = $true
        enableOutboundTracking = $true
        collectionCount  = 0
        lastCollection   = $null
        status           = "active"
    }
    Save-CollectorConfig $config

    $scriptPath = $MyInvocation.MyCommand.Path
    if (-not $scriptPath) { $scriptPath = "$BaseDir\PCPlus-NetworkCollector.ps1" }
    Copy-Item $MyInvocation.MyCommand.Path $BaseDir -Force -ErrorAction SilentlyContinue

    $existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($existingTask) { Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false }

    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$BaseDir\PCPlus-NetworkCollector.ps1`" -Mode collect"
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes) -RepetitionDuration (New-TimeSpan -Days $CollectionDays)
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew

    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "PC Plus Computing Network Security Assessment - collects security data for $CollectionDays days"

    # Run first collection immediately
    & $MyInvocation.MyCommand.Path -Mode collect

    Write-Host "=== PC Plus Network Security Collector Installed ===" -ForegroundColor Green
    Write-Host "Scheduled task: $TaskName" -ForegroundColor Cyan
    Write-Host "Interval: Every $IntervalMinutes minutes for $CollectionDays days" -ForegroundColor Cyan
    Write-Host "Network scanning: $(if(-not $DisableNetworkScan){'ENABLED'}else{'DISABLED'})" -ForegroundColor $(if(-not $DisableNetworkScan){'Green'}else{'Yellow'})
    Write-Host "Config: $ConfigPath" -ForegroundColor Gray
    Write-Host "Data: $DataDir" -ForegroundColor Gray
    exit 0
}

# ============================================================
# UNINSTALL MODE
# ============================================================
if ($Mode -eq 'uninstall') {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "Scheduled task removed" -ForegroundColor Green
    Write-Host "Data preserved at: $DataDir (delete manually if needed)" -ForegroundColor Yellow
    exit 0
}

# ============================================================
# STATUS MODE
# ============================================================
if ($Mode -eq 'status') {
    $cfg = Get-CollectorConfig
    if (-not $cfg) { Write-Host "Not installed. Run with -Mode install first." -ForegroundColor Red; exit 1 }

    $installDate = [DateTime]::Parse($cfg.installDate)
    $daysRunning = [Math]::Round(((Get-Date) - $installDate).TotalDays, 1)
    $dataFiles = (Get-ChildItem "$DataDir\collection_*.json" -ErrorAction SilentlyContinue).Count

    Write-Host "=== PC Plus Network Security Collector Status ===" -ForegroundColor Cyan
    Write-Host "Status: $($cfg.status)" -ForegroundColor $(if($cfg.status -eq 'active'){'Green'}else{'Yellow'})
    Write-Host "Installed: $($installDate.ToString('MMM d, yyyy h:mm tt'))" -ForegroundColor White
    Write-Host "Running for: $daysRunning days" -ForegroundColor White
    Write-Host "Collections: $($cfg.collectionCount)" -ForegroundColor White
    Write-Host "Data files: $dataFiles" -ForegroundColor White
    Write-Host "Last collection: $($cfg.lastCollection)" -ForegroundColor White
    Write-Host ""
    Write-Host "Features:" -ForegroundColor Yellow
    Write-Host "  Login events:     $(if($cfg.enableLoginEvents){'ON'}else{'OFF'})" -ForegroundColor $(if($cfg.enableLoginEvents){'Green'}else{'Red'})
    Write-Host "  Network scan:     $(if($cfg.enableNetworkScan){'ON'}else{'OFF'})" -ForegroundColor $(if($cfg.enableNetworkScan){'Green'}else{'Red'})
    Write-Host "  Port scan:        $(if($cfg.enablePortScan){'ON'}else{'OFF'})" -ForegroundColor $(if($cfg.enablePortScan){'Green'}else{'Red'})
    Write-Host "  Device discovery: $(if($cfg.enableDeviceDiscovery){'ON'}else{'OFF'})" -ForegroundColor $(if($cfg.enableDeviceDiscovery){'Green'}else{'Red'})
    Write-Host "  Service detect:   $(if($cfg.enableServiceDetection){'ON'}else{'OFF'})" -ForegroundColor $(if($cfg.enableServiceDetection){'Green'}else{'Red'})
    Write-Host "  Connection track: $(if($cfg.enableConnectionTracking){'ON'}else{'OFF'})" -ForegroundColor $(if($cfg.enableConnectionTracking){'Green'}else{'Red'})
    Write-Host "  DNS monitoring:   $(if($cfg.enableDnsMonitoring){'ON'}else{'OFF'})" -ForegroundColor $(if($cfg.enableDnsMonitoring){'Green'}else{'Red'})
    Write-Host "  PowerShell:       $(if($cfg.enablePowerShell){'ON'}else{'OFF'})" -ForegroundColor $(if($cfg.enablePowerShell){'Green'}else{'Red'})
    Write-Host "  Defender:         $(if($cfg.enableDefender){'ON'}else{'OFF'})" -ForegroundColor $(if($cfg.enableDefender){'Green'}else{'Red'})
    exit 0
}

# ============================================================
# COLLECT MODE
# ============================================================
if ($Mode -eq 'collect') {
    $ErrorActionPreference = "SilentlyContinue"
    New-Item -Path $DataDir -ItemType Directory -Force | Out-Null

    $cfg = Get-CollectorConfig
    if (-not $cfg) {
        $cfg = @{
            enableLoginEvents = $true; enableNetworkScan = $true; enablePortScan = $true
            enablePowerShell = $true; enableDefender = $true; enableDeviceDiscovery = $true
            enableServiceDetection = $true; enableConnectionTracking = $true
            enableDnsMonitoring = $true; enableOutboundTracking = $true
            collectionCount = 0; status = "active"
        }
    }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $collection = @{
        timestamp = (Get-Date -Format "o")
        computerName = $env:COMPUTERNAME
        data = @{}
    }

    # --- LOGIN EVENTS ---
    if ($cfg.enableLoginEvents) {
        $lastCollectionFile = "$DataDir\last_event_time.txt"
        $lookbackTime = if (Test-Path $lastCollectionFile) {
            [DateTime]::Parse((Get-Content $lastCollectionFile -Raw).Trim())
        } else {
            (Get-Date).AddHours(-1)
        }

        $failedLogins = @()
        $successLogins = @()
        $lockouts = @()
        $accountChanges = @()
        $privilegeEvents = @()

        # Failed logins (4625)
        try {
            $events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=$lookbackTime} -MaxEvents 2000 2>$null
            foreach ($evt in $events) {
                $xml = [xml]$evt.ToXml()
                $d = @{}; foreach ($x in $xml.Event.EventData.Data) { $d[$x.Name] = $x.'#text' }
                $lt = [int]$d['LogonType']; if ($lt -eq 0 -or $lt -eq 5) { continue }
                $user = $d['TargetUserName']; if ($user -eq '-' -or $user -eq 'SYSTEM' -or $user -match '\$$') { continue }
                $ip = $d['IpAddress']; if ($ip -eq '-' -or $ip -eq '::1' -or $ip -eq '127.0.0.1') { $ip = 'Local' }

                $failedLogins += @{
                    time = $evt.TimeCreated.ToString("o"); user = $d['TargetUserName']; domain = $d['TargetDomainName']
                    ip = $ip; port = $d['IpPort']
                    logonType = switch($lt){2{"Interactive"};3{"Network/SMB"};7{"Unlock"};8{"NetworkCleartext"};10{"RDP"};11{"Cached"};default{"Type$lt"}}
                    logonTypeId = $lt; status = $d['Status']; subStatus = $d['SubStatus']
                    reason = switch($d['Status']){'0xC000006D'{"Bad credentials"};'0xC000006A'{"Wrong password"};'0xC0000064'{"Unknown user"};'0xC0000234'{"Locked out"};'0xC0000072'{"Disabled"};'0xC000006F'{"Outside hours"};'0xC0000071'{"Password expired"};'0xC000015B'{"Logon type denied"};default{$d['Status']}}
                    workstation = $d['WorkstationName']; process = $d['ProcessName']
                    protocol = $(if($lt-eq10){"RDP"}elseif($lt-eq3){"SMB"}else{"Local"})
                }
            }
        } catch {}

        # Successful logins (4624)
        try {
            $events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=$lookbackTime} -MaxEvents 2000 2>$null
            foreach ($evt in $events) {
                $xml = [xml]$evt.ToXml()
                $d = @{}; foreach ($x in $xml.Event.EventData.Data) { $d[$x.Name] = $x.'#text' }
                $lt = [int]$d['LogonType']; if ($lt -eq 0 -or $lt -eq 5) { continue }
                $user = $d['TargetUserName']
                if ($user -eq '-' -or $user -eq 'SYSTEM' -or $user -eq 'LOCAL SERVICE' -or $user -eq 'NETWORK SERVICE' -or $user -eq 'ANONYMOUS LOGON' -or $user -match '\$$') { continue }
                $ip = $d['IpAddress']; if ($ip -eq '-' -or $ip -eq '::1' -or $ip -eq '127.0.0.1') { $ip = 'Local' }

                $successLogins += @{
                    time = $evt.TimeCreated.ToString("o"); user = $d['TargetUserName']; domain = $d['TargetDomainName']
                    ip = $ip; logonType = switch($lt){2{"Interactive"};3{"Network/SMB"};7{"Unlock"};10{"RDP"};11{"Cached"};default{"Type$lt"}}
                    logonTypeId = $lt; process = $d['ProcessName']
                    protocol = $(if($lt-eq10){"RDP"}elseif($lt-eq3){"SMB"}else{"Local"})
                }
            }
        } catch {}

        # Lockouts (4740)
        try {
            $events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4740; StartTime=$lookbackTime} -MaxEvents 500 2>$null
            foreach ($evt in $events) {
                $xml = [xml]$evt.ToXml(); $d = @{}; foreach ($x in $xml.Event.EventData.Data) { $d[$x.Name] = $x.'#text' }
                $lockouts += @{ time = $evt.TimeCreated.ToString("o"); user = $d['TargetUserName']; source = $d['TargetDomainName'] }
            }
        } catch {}

        # Account changes (4720/4726/4732/4733/4723/4724)
        try {
            $events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=@(4720,4726,4732,4733,4723,4724); StartTime=$lookbackTime} -MaxEvents 500 2>$null
            foreach ($evt in $events) {
                $xml = [xml]$evt.ToXml(); $d = @{}; foreach ($x in $xml.Event.EventData.Data) { $d[$x.Name] = $x.'#text' }
                $accountChanges += @{
                    time = $evt.TimeCreated.ToString("o"); eventId = $evt.Id
                    type = switch($evt.Id){4720{"Account Created"};4726{"Account Deleted"};4732{"Added to Group"};4733{"Removed from Group"};4723{"Password Changed"};4724{"Password Reset"}}
                    target = $d['TargetUserName']; by = $d['SubjectUserName']
                    group = if ($evt.Id -in 4732,4733) { $d['TargetUserName'] } else { '' }
                }
            }
        } catch {}

        # Privilege escalation (4672) and explicit credentials (4648)
        try {
            $events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=@(4672,4648); StartTime=$lookbackTime} -MaxEvents 500 2>$null
            foreach ($evt in $events) {
                $xml = [xml]$evt.ToXml(); $d = @{}; foreach ($x in $xml.Event.EventData.Data) { $d[$x.Name] = $x.'#text' }
                $user = if ($evt.Id -eq 4672) { $d['SubjectUserName'] } else { $d['TargetUserName'] }
                if ($user -eq 'SYSTEM' -or $user -eq '-' -or $user -match '\$$') { continue }
                $privilegeEvents += @{
                    time = $evt.TimeCreated.ToString("o"); eventId = $evt.Id; user = $user
                    type = if ($evt.Id -eq 4672) { "Special Privileges" } else { "Explicit Credentials (RunAs)" }
                    target = if ($evt.Id -eq 4648) { $d['TargetServerName'] } else { '' }
                }
            }
        } catch {}

        # SSH (OpenSSH)
        $sshEvents = @()
        try {
            $events = Get-WinEvent -FilterHashtable @{LogName='OpenSSH/Operational'; StartTime=$lookbackTime} -MaxEvents 500 2>$null
            foreach ($evt in $events) {
                $msg = $evt.FormatDescription()
                if ($msg -match '(Accepted|authenticated|Failed|Invalid user|refused)') {
                    $ipMatch = [regex]::Match($msg, '(\d+\.\d+\.\d+\.\d+)')
                    $userMatch = [regex]::Match($msg, '(?:user|for)\s+(\S+)')
                    $sshEvents += @{
                        time = $evt.TimeCreated.ToString("o")
                        type = if ($msg -match 'Accepted|authenticated') { "success" } else { "failed" }
                        user = if ($userMatch.Success) { $userMatch.Groups[1].Value } else { "unknown" }
                        ip = if ($ipMatch.Success) { $ipMatch.Groups[1].Value } else { "" }
                        message = $msg.Substring(0, [Math]::Min($msg.Length, 200))
                    }
                }
            }
        } catch {}

        $collection.data.failedLogins = $failedLogins
        $collection.data.successLogins = $successLogins
        $collection.data.lockouts = $lockouts
        $collection.data.accountChanges = $accountChanges
        $collection.data.privilegeEvents = $privilegeEvents
        $collection.data.sshEvents = $sshEvents

        (Get-Date).ToString("o") | Out-File $lastCollectionFile -Encoding UTF8 -Force
    }

    # --- NETWORK DEVICE DISCOVERY ---
    if ($cfg.enableDeviceDiscovery -and $cfg.enableNetworkScan) {
        $devices = @()
        try {
            # Ping sweep the local subnet first to populate ARP cache
            $localIP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' -and $_.PrefixOrigin -ne 'WellKnown' } | Select-Object -First 1).IPAddress
            if ($localIP) {
                $subnet = $localIP -replace '\.\d+$', ''
                $jobs = @()
                1..254 | ForEach-Object {
                    $jobs += Test-Connection -ComputerName "$subnet.$_" -Count 1 -AsJob -ErrorAction SilentlyContinue
                }
                $jobs | Wait-Job -Timeout 10 | Out-Null
                $jobs | Remove-Job -Force -ErrorAction SilentlyContinue
            }

            # Now read ARP table
            $arpOutput = arp -a
            $vendorMap = @{
                'D8BBC1'='Dell'; '001DD8'='Microsoft'; '005056'='VMware'; '000C29'='VMware'; '00155D'='Hyper-V'
                '14B31F'='Dell'; 'F8B156'='Dell'; 'B083FE'='Dell'; '4CCC6A'='Dell'; 'A4BB6D'='Dell'
                '001635'='HP'; '3C4A92'='HP'; '18A905'='HP'; '94B866'='HP'; '80E82C'='HP'; '2C44FD'='HP'
                '3CA82A'='Intel'; 'A0369F'='Intel'; 'DC536C'='Intel'; 'ECEBB8'='Intel'; '485B39'='Intel'
                'AC220B'='ASUS'; '305A3A'='ASUS'
                '60455E'='Apple'; 'A860B6'='Apple'; 'DC2B2A'='Apple'; '3C22FB'='Apple'
                'A4CF12'='Cisco'; '001921'='Cisco'; '000C85'='Cisco'; '001BD4'='Cisco'; '0024C4'='Cisco'
                '001122'='Synology'; '0011A3'='Synology'
                'EC086B'='TP-Link'; '50C7BF'='TP-Link'; '60A4B7'='TP-Link'; 'B0BE76'='TP-Link'
                '001E58'='D-Link'; '28107B'='D-Link'
                '00256B'='Netgear'; 'E091F5'='Netgear'; 'B07FB9'='Netgear'
                '34298F'='Lenovo'; '5CF7E6'='Lenovo'
                '001CBF'='QNAP'; '24A2E1'='QNAP'
                '0050F2'='Microsoft'; 'FCF528'='ZyXEL'; 'D4F5EF'='ZyXEL'
                '001217'='Linksys'; '74E5F9'='Liteon'
                '002275'='Western Digital'; '48B02D'='NVIDIA'
                '88366C'='EFI'; '001A7D'='Cyber-Rain'; '001F4B'='Yamaha'
                '000625'='Xerox'; 'D85DE2'='Epson'; '001B63'='Canon'; '000E7B'='Toshiba'
                '0021B7'='Lexmark'; '00117E'='Midmark'; 'B0ACFA'='Ubiquiti'; 'F09FC2'='Ubiquiti'
                '44D9E7'='Ubiquiti'; '802AA8'='Ubiquiti'; '24A43C'='Ubiquiti'; 'FC15B4'='Amazon'
                '34AF2C'='Amazon'; 'A0F3C1'='Amazon'; '4CEFC0'='EnGenius'; '0025B3'='HP Enterprise'
            }

            foreach ($line in $arpOutput) {
                if ($line -match '(\d+\.\d+\.\d+\.\d+)\s+([\da-f-]+)\s+(\w+)') {
                    $ip = $Matches[1]; $mac = $Matches[2].ToUpper(); $type = $Matches[3]
                    if ($mac -eq 'FF-FF-FF-FF-FF-FF' -or $ip -match '\.(255|0)$') { continue }

                    $prefix = ($mac -replace '-','').Substring(0,6)
                    $vendor = if ($vendorMap.ContainsKey($prefix)) { $vendorMap[$prefix] } else { '' }
                    $hostname = ''; try { $hostname = [System.Net.Dns]::GetHostEntry($ip).HostName } catch {}

                    $dev = @{ ip = $ip; mac = $mac; vendor = $vendor; hostname = $hostname; type = $type }

                    # Service detection on discovered device
                    if ($cfg.enableServiceDetection) {
                        $services = @()
                        $commonPorts = @{22='SSH';23='Telnet';25='SMTP';53='DNS';80='HTTP';443='HTTPS';445='SMB';631='IPP/Printer';3389='RDP';5000='Synology/UPnP';8080='HTTP-Alt';8443='HTTPS-Alt';9100='Print';161='SNMP';548='AFP';139='NetBIOS';5900='VNC'}
                        foreach ($port in $commonPorts.Keys) {
                            try {
                                $tcp = New-Object System.Net.Sockets.TcpClient
                                $connect = $tcp.BeginConnect($ip, $port, $null, $null)
                                $wait = $connect.AsyncWaitHandle.WaitOne(150, $false)
                                if ($wait -and $tcp.Connected) {
                                    $services += @{ port = $port; service = $commonPorts[$port] }
                                }
                                $tcp.Close()
                            } catch {}
                        }
                        $dev.services = $services

                        # Guess device type from services
                        $dev.deviceType = if ($services.service -contains 'Print' -or $services.service -contains 'IPP/Printer') { 'Printer' }
                            elseif ($services.service -contains 'SMB' -and $services.service -contains 'RDP') { 'Windows PC/Server' }
                            elseif ($services.service -contains 'SSH' -and $services.service -contains 'SMB') { 'Linux/NAS' }
                            elseif ($services.service -contains 'Synology/UPnP') { 'NAS/Media' }
                            elseif ($services.service -contains 'HTTP' -or $services.service -contains 'HTTPS') { 'Web Device' }
                            elseif ($vendor -match 'Cisco|Netgear|TP-Link|D-Link|Ubiquiti|ZyXEL|Linksys|EnGenius') { 'Network Equipment' }
                            elseif ($vendor -match 'Apple') { 'Apple Device' }
                            elseif ($services.Count -eq 0 -and $vendor) { "$vendor Device" }
                            else { 'Unknown' }
                    }

                    $devices += $dev
                }
            }
        } catch {}
        $collection.data.devices = $devices
    }

    # --- OPEN PORTS ---
    if ($cfg.enablePortScan) {
        $openPorts = @()
        try {
            $connections = Get-NetTCPConnection -State Listen 2>$null
            $knownPorts = @{
                21='FTP';22='SSH';23='Telnet';25='SMTP';53='DNS';80='HTTP';88='Kerberos'
                110='POP3';135='RPC';139='NetBIOS';143='IMAP';389='LDAP';443='HTTPS'
                445='SMB';465='SMTPS';587='Submission';636='LDAPS';993='IMAPS';995='POP3S'
                1433='SQL Server';1434='SQL Browser';3306='MySQL';3389='RDP';5432='PostgreSQL'
                5900='VNC';5985='WinRM';5986='WinRM-SSL';8080='HTTP-Proxy';8443='Alt-HTTPS'
                9200='Elasticsearch';27017='MongoDB';6379='Redis';11211='Memcached'
            }
            foreach ($conn in $connections) {
                $port = $conn.LocalPort; $addr = $conn.LocalAddress
                if ($port -ge 50000) { continue }
                $pname = ''; try { $pname = (Get-Process -Id $conn.OwningProcess).ProcessName } catch {}
                $svc = if ($knownPorts.ContainsKey($port)) { $knownPorts[$port] } else { "Port $port" }
                $exposed = ($addr -eq '0.0.0.0' -or $addr -eq '::')
                $risk = if ($port -in 23,21,1433,3306,5432,5900,27017,6379,11211 -and $exposed) { 'Critical' }
                    elseif ($port -in 445,3389,135,139 -and $exposed) { 'High' }
                    elseif ($port -in 22,80,443,8080 -and $exposed) { 'Medium' }
                    elseif ($exposed -and $port -lt 1024) { 'Medium' }
                    else { 'Low' }

                $openPorts += @{ port = $port; service = $svc; address = "$addr"; process = $pname; pid = $conn.OwningProcess; exposed = $exposed; risk = $risk }
            }
        } catch {}
        $collection.data.openPorts = $openPorts | Sort-Object { $_.port } -Unique
    }

    # --- CONNECTION TRACKING ---
    if ($cfg.enableConnectionTracking) {
        $outbound = @()
        try {
            $established = Get-NetTCPConnection -State Established 2>$null | Where-Object { $_.RemoteAddress -notmatch '^(127\.|::1|0\.0\.0\.0)' }
            foreach ($conn in $established) {
                $pname = ''; try { $pname = (Get-Process -Id $conn.OwningProcess).ProcessName } catch {}
                $outbound += @{
                    localPort = $conn.LocalPort; remoteIP = $conn.RemoteAddress.ToString(); remotePort = $conn.RemotePort
                    process = $pname; pid = $conn.OwningProcess
                }
            }
        } catch {}

        # Group by remote IP for summary
        $connSummary = @()
        $grouped = $outbound | Group-Object { $_.remoteIP }
        foreach ($g in ($grouped | Sort-Object Count -Descending | Select-Object -First 50)) {
            $processes = ($g.Group | Select-Object -ExpandProperty process -Unique) -join ', '
            $ports = ($g.Group | Select-Object -ExpandProperty remotePort -Unique | Sort-Object) -join ', '
            $connSummary += @{ ip = $g.Name; count = $g.Count; processes = $processes; remotePorts = $ports }
        }
        $collection.data.outboundConnections = $connSummary
        $collection.data.outboundTotal = $outbound.Count
    }

    # --- DNS CACHE ---
    if ($cfg.enableDnsMonitoring) {
        $dnsCache = @()
        try {
            $cache = Get-DnsClientCache 2>$null | Where-Object { $_.Entry -notmatch '\.local$|^_' } | Select-Object -First 100
            foreach ($entry in $cache) {
                $dnsCache += @{ name = $entry.Entry; type = $entry.Type.ToString(); data = $entry.Data; ttl = $entry.TimeToLive }
            }
        } catch {}
        $collection.data.dnsCache = $dnsCache
    }

    # --- POWERSHELL SUSPICIOUS ACTIVITY ---
    if ($cfg.enablePowerShell) {
        $lookbackPS = if (Test-Path "$DataDir\last_event_time.txt") {
            [DateTime]::Parse((Get-Content "$DataDir\last_event_time.txt" -Raw).Trim())
        } else { (Get-Date).AddHours(-1) }

        $psActivity = @()
        try {
            $events = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104; StartTime=$lookbackPS} -MaxEvents 200 2>$null
            $patterns = @('Invoke-WebRequest','Invoke-Expression','IEX','DownloadString','DownloadFile','Start-BitsTransfer',
                'New-Object Net.WebClient','Bypass','Hidden','EncodedCommand','-enc ','FromBase64',
                'Mimikatz','sekurlsa','kerberos::','Invoke-ReflectivePEInjection','Invoke-Shellcode',
                'Set-MpPreference -Disable','Add-MpPreference -Exclusion','vssadmin delete','wbadmin delete',
                'bcdedit /set','Remove-MpPreference','Invoke-Command -ComputerName','Enter-PSSession',
                'certutil -decode','certutil -urlcache','regsvr32 /s /n /u','mshta','wmic process call create',
                'Invoke-WmiMethod','Invoke-CimMethod.*create','schtasks /create.*cmd','bitsadmin /transfer')

            foreach ($evt in $events) {
                $script = $evt.Properties[2].Value.ToString()
                foreach ($p in $patterns) {
                    if ($script -match [regex]::Escape($p)) {
                        $psActivity += @{
                            time = $evt.TimeCreated.ToString("o"); pattern = $p
                            script = $script.Substring(0, [Math]::Min($script.Length, 300))
                        }
                        break
                    }
                }
            }
        } catch {}
        $collection.data.suspiciousPowerShell = $psActivity
    }

    # --- DEFENDER & SECURITY STATUS ---
    if ($cfg.enableDefender) {
        $secStatus = @{}
        try {
            $mp = Get-MpComputerStatus 2>$null
            if ($mp) {
                $secStatus.defender = @{
                    realTime = $mp.RealTimeProtectionEnabled; antivirusEnabled = $mp.AntivirusEnabled
                    signatureAge = $mp.AntivirusSignatureAge; lastScan = $mp.QuickScanEndTime.ToString("o")
                    tamperProtection = $mp.IsTamperProtected; behaviorMonitor = $mp.BehaviorMonitorEnabled
                    cloudProtection = ($mp.MAPSReporting -ne 0); engineVersion = $mp.AMEngineVersion
                    signatureVersion = $mp.AntivirusSignatureVersion
                }
            }
        } catch {}

        try {
            $fw = Get-NetFirewallProfile 2>$null
            $secStatus.firewall = @{}
            foreach ($p in $fw) { $secStatus.firewall[$p.Name] = $p.Enabled }
        } catch {}

        try {
            $bl = Get-BitLockerVolume -MountPoint "C:" 2>$null
            $secStatus.bitlocker = if ($bl) { $bl.ProtectionStatus.ToString() } else { "Not Available" }
        } catch { $secStatus.bitlocker = "Not Available" }

        try {
            $hf = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1
            $secStatus.lastPatch = if ($hf.InstalledOn) { $hf.InstalledOn.ToString("yyyy-MM-dd") } else { "Unknown" }
            $secStatus.patchCount = (Get-HotFix).Count
        } catch {}

        # Installed AV products
        try {
            $av = Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName AntiVirusProduct 2>$null
            $secStatus.avProducts = @()
            foreach ($a in $av) {
                $state = $a.productState
                $enabled = (($state -shr 12) -band 0xF) -eq 1
                $secStatus.avProducts += @{ name = $a.displayName; enabled = $enabled }
            }
        } catch {}

        $collection.data.securityStatus = $secStatus
    }

    # --- NETWORK INTERFACES ---
    $netInfo = @()
    try {
        $adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
        foreach ($a in $adapters) {
            $ipAddr = (Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress
            $stats = Get-NetAdapterStatistics -Name $a.Name -ErrorAction SilentlyContinue
            $netInfo += @{
                name = $a.Name; description = $a.InterfaceDescription; mac = $a.MacAddress
                speed = $a.LinkSpeed; ip = $ipAddr; status = $a.Status.ToString()
                bytesReceived = if ($stats) { $stats.ReceivedBytes } else { 0 }
                bytesSent = if ($stats) { $stats.SentBytes } else { 0 }
            }
        }
    } catch {}
    $collection.data.networkInterfaces = $netInfo

    # --- SHARED FOLDERS ---
    $shares = @()
    try {
        $smbShares = Get-SmbShare 2>$null | Where-Object { $_.Name -notmatch '^\$' -and $_.Name -ne 'IPC$' }
        foreach ($s in $smbShares) {
            $access = @()
            try { $access = (Get-SmbShareAccess -Name $s.Name 2>$null | Select-Object -ExpandProperty AccountName) } catch {}
            $shares += @{ name = $s.Name; path = $s.Path; description = $s.Description; access = $access -join ', ' }
        }
    } catch {}
    $collection.data.sharedFolders = $shares

    # --- SCHEDULED TASKS (suspicious) ---
    $suspTasks = @()
    try {
        $tasks = Get-ScheduledTask 2>$null | Where-Object { $_.State -eq 'Ready' -or $_.State -eq 'Running' }
        $suspPatterns = @('powershell','cmd.exe /c','wscript','cscript','mshta','regsvr32','certutil','bitsadmin','msiexec /q')
        foreach ($t in $tasks) {
            foreach ($action in $t.Actions) {
                $exe = "$($action.Execute) $($action.Arguments)"
                foreach ($p in $suspPatterns) {
                    if ($exe -match [regex]::Escape($p)) {
                        $suspTasks += @{
                            name = $t.TaskName; path = $t.TaskPath; state = $t.State.ToString()
                            execute = $action.Execute; arguments = $action.Arguments
                            matchedPattern = $p
                        }
                        break
                    }
                }
            }
        }
    } catch {}
    $collection.data.suspiciousScheduledTasks = $suspTasks

    # --- RUNNING SERVICES ---
    $services = @()
    try {
        $svcs = Get-Service | Where-Object { $_.Status -eq 'Running' -and $_.StartType -ne 'Disabled' }
        foreach ($s in $svcs) {
            $services += @{ name = $s.Name; displayName = $s.DisplayName; startType = $s.StartType.ToString() }
        }
    } catch {}
    $collection.data.runningServices = $services

    # --- SAVE COLLECTION ---
    $collectionPath = "$DataDir\collection_$timestamp.json"
    $collection | ConvertTo-Json -Depth 6 -Compress | Out-File $collectionPath -Encoding UTF8 -Force

    # Update config
    if ($cfg -is [PSCustomObject]) {
        $cfg.collectionCount = $cfg.collectionCount + 1
        $cfg.lastCollection = (Get-Date -Format "o")
        Save-CollectorConfig $cfg
    }

    # Cleanup old collections (keep last 2000)
    $allFiles = Get-ChildItem "$DataDir\collection_*.json" | Sort-Object Name
    if ($allFiles.Count -gt 2000) {
        $allFiles | Select-Object -First ($allFiles.Count - 2000) | Remove-Item -Force
    }

    Write-Host "Collection #$($cfg.collectionCount) saved: $collectionPath" -ForegroundColor Green
    Write-Host "  Failed logins: $($failedLogins.Count) | Success: $($successLogins.Count) | Devices: $($devices.Count) | Ports: $($openPorts.Count)" -ForegroundColor Cyan
    exit 0
}

# ============================================================
# REPORT MODE - Aggregate all collected data into HTML report
# ============================================================
if ($Mode -eq 'report') {
    $cfg = Get-CollectorConfig
    $collectionFiles = Get-ChildItem "$DataDir\collection_*.json" | Sort-Object Name
    if ($collectionFiles.Count -eq 0) { Write-Host "No data collected yet. Run -Mode collect first." -ForegroundColor Red; exit 1 }

    Write-Host "=== Generating Report from $($collectionFiles.Count) collections ===" -ForegroundColor Cyan

    # Aggregate all data
    $allFailed = @(); $allSuccess = @(); $allLockouts = @(); $allAccountChanges = @()
    $allPrivilege = @(); $allSSH = @(); $allPS = @(); $allSuspTasks = @()
    $deviceMap = @{}; $portMap = @{}; $connMap = @{}
    $latestSecurity = $null; $latestShares = @(); $latestInterfaces = @()
    $latestServices = @()

    foreach ($file in $collectionFiles) {
        try {
            $data = Get-Content $file.FullName -Raw | ConvertFrom-Json
            $d = $data.data

            if ($d.failedLogins) { $allFailed += $d.failedLogins }
            if ($d.successLogins) { $allSuccess += $d.successLogins }
            if ($d.lockouts) { $allLockouts += $d.lockouts }
            if ($d.accountChanges) { $allAccountChanges += $d.accountChanges }
            if ($d.privilegeEvents) { $allPrivilege += $d.privilegeEvents }
            if ($d.sshEvents) { $allSSH += $d.sshEvents }
            if ($d.suspiciousPowerShell) { $allPS += $d.suspiciousPowerShell }
            if ($d.suspiciousScheduledTasks) { $allSuspTasks += $d.suspiciousScheduledTasks }
            if ($d.securityStatus) { $latestSecurity = $d.securityStatus }
            if ($d.sharedFolders) { $latestShares = $d.sharedFolders }
            if ($d.networkInterfaces) { $latestInterfaces = $d.networkInterfaces }
            if ($d.runningServices) { $latestServices = $d.runningServices }

            if ($d.devices) {
                foreach ($dev in $d.devices) {
                    $deviceMap[$dev.mac] = $dev
                }
            }
            if ($d.openPorts) {
                foreach ($p in $d.openPorts) { $portMap["$($p.port)"] = $p }
            }
            if ($d.outboundConnections) {
                foreach ($c in $d.outboundConnections) {
                    if (-not $connMap[$c.ip]) { $connMap[$c.ip] = @{ ip = $c.ip; totalCount = 0; processes = @(); ports = @() } }
                    $connMap[$c.ip].totalCount += $c.count
                    $connMap[$c.ip].processes += ($c.processes -split ', ')
                    $connMap[$c.ip].ports += ($c.remotePorts -split ', ')
                }
            }
        } catch { Write-Host "  Skipping corrupt file: $($file.Name)" -ForegroundColor Yellow }
    }

    # Deduplicate
    $allFailed = $allFailed | Sort-Object { $_.time } -Unique
    $allSuccess = $allSuccess | Sort-Object { $_.time } -Unique

    # Collection period
    $firstCollection = if ($cfg.installDate) { [DateTime]::Parse($cfg.installDate) } else { (Get-Date).AddDays(-7) }
    $daysCollected = [Math]::Round(((Get-Date) - $firstCollection).TotalDays, 1)

    Write-Host "  Period: $daysCollected days ($($collectionFiles.Count) collections)"
    Write-Host "  Failed logins: $($allFailed.Count)"
    Write-Host "  Successful logins: $($allSuccess.Count)"
    Write-Host "  Devices: $($deviceMap.Count)"
    Write-Host "  Open ports: $($portMap.Count)"

    # Brute force analysis
    $bruteForce = @()
    $failedByIP = $allFailed | Where-Object { $_.ip -ne 'Local' -and $_.ip } | Group-Object { $_.ip }
    foreach ($g in $failedByIP) {
        if ($g.Count -ge 5) {
            $times = $g.Group | ForEach-Object { [DateTime]::Parse($_.time) } | Sort-Object
            $accounts = ($g.Group | Select-Object -ExpandProperty user -Unique) -join ', '
            $protocols = ($g.Group | ForEach-Object { $_.protocol } | Select-Object -Unique) -join ', '

            $succeeded = $allSuccess | Where-Object { $_.ip -eq $g.Name }
            $compromised = $false
            foreach ($s in $succeeded) {
                $sTime = [DateTime]::Parse($s.time)
                if ($times | Where-Object { $_ -lt $sTime }) { $compromised = $true; break }
            }

            $bruteForce += [PSCustomObject]@{
                IP = $g.Name; Count = $g.Count; Accounts = $accounts; Protocols = $protocols
                First = $times[0].ToString("MMM d, HH:mm"); Last = $times[-1].ToString("MMM d, HH:mm")
                Compromised = $compromised
                Severity = if ($compromised) { 'CRITICAL' } elseif ($g.Count -ge 50) { 'CRITICAL' } elseif ($g.Count -ge 20) { 'HIGH' } elseif ($g.Count -ge 10) { 'MEDIUM' } else { 'LOW' }
            }
        }
    }
    $bruteForce = $bruteForce | Sort-Object Count -Descending

    # Risk score
    $score = 100; $risks = @()
    if ($bruteForce.Count -gt 0) { $d = [Math]::Min($bruteForce.Count * 5, 25); $score -= $d; $risks += "Brute force attacks: $($bruteForce.Count) sources (-$d)" }
    if ($bruteForce | Where-Object { $_.Compromised }) { $score -= 30; $risks += "COMPROMISED ACCOUNTS detected (-30)" }
    if ($allLockouts.Count -gt 5) { $score -= 10; $risks += "Account lockouts: $($allLockouts.Count) (-10)" }
    if ($allPS.Count -gt 0) { $d = [Math]::Min($allPS.Count * 3, 15); $score -= $d; $risks += "Suspicious PowerShell: $($allPS.Count) events (-$d)" }
    $hiPorts = $portMap.Values | Where-Object { $_.risk -in 'Critical','High' }
    if ($hiPorts.Count -gt 0) { $d = [Math]::Min($hiPorts.Count * 5, 20); $score -= $d; $risks += "Critical/High risk ports: $($hiPorts.Count) (-$d)" }
    if ($latestSecurity.defender -and -not $latestSecurity.defender.realTime) { $score -= 15; $risks += "Real-time protection OFF (-15)" }
    if ($latestSecurity.defender.signatureAge -gt 7) { $score -= 10; $risks += "AV signatures $($latestSecurity.defender.signatureAge) days old (-10)" }
    if ($latestSecurity.firewall.Values -contains $false) { $score -= 10; $risks += "Firewall profile disabled (-10)" }
    if ($latestSecurity.bitlocker -ne 'On') { $score -= 5; $risks += "Drive encryption off (-5)" }
    $rdpFailed = $allFailed | Where-Object { $_.protocol -eq 'RDP' }
    if ($rdpFailed.Count -gt 50) { $d = [Math]::Min(15, [int]($rdpFailed.Count / 10)); $score -= $d; $risks += "RDP attacks: $($rdpFailed.Count) attempts (-$d)" }
    if ($allSuspTasks.Count -gt 0) { $score -= 5; $risks += "Suspicious scheduled tasks: $($allSuspTasks.Count) (-5)" }
    if ($latestShares.Count -gt 0) { $score -= 3; $risks += "Shared folders exposed: $($latestShares.Count) (-3)" }
    $score = [Math]::Max(0, $score)
    $grade = switch ($score) { { $_ -ge 90 } { 'A' }; { $_ -ge 80 } { 'B' }; { $_ -ge 70 } { 'C' }; { $_ -ge 60 } { 'D' }; default { 'F' } }
    $gradeColor = switch ($score) { { $_ -ge 80 } { '#10b981' }; { $_ -ge 60 } { '#f59e0b' }; default { '#ef4444' } }

    # Now call the original report script with aggregated data
    # For speed, generate inline
    $reportPath = "$BaseDir\report.html"

    # Build HTML sections
    $computerName = $env:COMPUTERNAME
    $scanDate = Get-Date -Format "MMMM d, yyyy h:mm tt"
    $osInfo = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption

    # I'll invoke the original scan script in report-from-data mode
    # For now, save the aggregated JSON and call the report script
    $aggregated = @{
        scanDate = $scanDate; computerName = $computerName; osInfo = $osInfo
        collectionPeriod = "$daysCollected days"; collectionCount = $collectionFiles.Count
        riskScore = $score; riskGrade = $grade
        failedLogins = $allFailed.Count; successLogins = $allSuccess.Count
        lockouts = $allLockouts.Count; bruteForceCount = $bruteForce.Count
        devices = $deviceMap.Count; openPorts = $portMap.Count
        suspiciousPS = $allPS.Count; accountChanges = $allAccountChanges.Count
        rdpFailed = $rdpFailed.Count
        rdpSuccess = ($allSuccess | Where-Object { $_.protocol -eq 'RDP' }).Count
        riskFactors = $risks
        bruteForce = $bruteForce | Select-Object -First 20
    }

    $aggregated | ConvertTo-Json -Depth 5 | Out-File "$BaseDir\aggregated_data.json" -Encoding UTF8 -Force

    # Generate report using the standalone scanner with aggregated data
    & "$PSScriptRoot\PCPlus-NetworkSecurityScan.ps1" -DaysBack ([int]$daysCollected) -OutputDir $BaseDir

    Write-Host "`n=== REPORT GENERATED ===" -ForegroundColor Green
    Write-Host "Score: $score/100 ($grade)" -ForegroundColor $(if($score -ge 80){'Green'}elseif($score -ge 60){'Yellow'}else{'Red'})
    Write-Host "Period: $daysCollected days ($($collectionFiles.Count) collections)" -ForegroundColor Cyan
    Write-Host "Report: $reportPath" -ForegroundColor Cyan
    exit 0
}
