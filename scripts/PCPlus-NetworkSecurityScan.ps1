<#
.SYNOPSIS
    PC Plus Computing - Network Security Scanner
    Collects security events, discovers network devices, detects threats
    Generates branded HTML report for customer presentation
.DESCRIPTION
    Deploy via Tactical RMM. Runs as admin on one machine per site.
    Outputs: C:\ProgramData\PCPlusEndpoint\NetworkSecurity\report.html
#>

param(
    [int]$DaysBack = 7,
    [string]$OutputDir = "$env:ProgramData\PCPlusEndpoint\NetworkSecurity",
    [switch]$OpenReport
)

$ErrorActionPreference = "SilentlyContinue"
New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null

Write-Host "=== PC Plus Computing Network Security Scanner ===" -ForegroundColor Cyan
Write-Host "Scanning last $DaysBack days..." -ForegroundColor Gray

# ============================================================
# 1. FAILED LOGIN ATTEMPTS (Event 4625)
# ============================================================
Write-Host "[1/10] Collecting failed login attempts..." -ForegroundColor Yellow
$failedLogins = @()
try {
    $events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddDays(-$DaysBack)} -MaxEvents 5000 2>$null
    foreach ($evt in $events) {
        $xml = [xml]$evt.ToXml()
        $data = @{}
        foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }

        $logonType = [int]$data['LogonType']
        if ($logonType -eq 0 -or $logonType -eq 5) { continue }

        $user = $data['TargetUserName']
        if ($user -eq '-' -or $user -eq 'SYSTEM' -or $user -match '\$$') { continue }

        $ip = $data['IpAddress']
        if ($ip -eq '-' -or $ip -eq '::1' -or $ip -eq '127.0.0.1') { $ip = 'Local' }

        $logonTypeName = switch ($logonType) {
            2  { "Interactive" }
            3  { "Network/SMB" }
            7  { "Unlock" }
            8  { "NetworkCleartext" }
            10 { "RDP" }
            11 { "Cached" }
            default { "Type $logonType" }
        }

        $reason = switch ($data['Status']) {
            '0xC000006D' { "Bad username or password" }
            '0xC000006A' { "Incorrect password" }
            '0xC0000064' { "User does not exist" }
            '0xC0000234' { "Account locked out" }
            '0xC0000072' { "Account disabled" }
            '0xC000006F' { "Outside authorized hours" }
            '0xC0000071' { "Password expired" }
            default { $data['Status'] }
        }

        $failedLogins += [PSCustomObject]@{
            Time        = $evt.TimeCreated
            Username    = if ($data['TargetDomainName'] -and $data['TargetDomainName'] -ne '-') { "$($data['TargetDomainName'])\$user" } else { $user }
            SourceIP    = $ip
            LogonType   = $logonTypeName
            Reason      = $reason
            Workstation = $data['WorkstationName']
            Protocol    = if ($logonType -eq 10) { "RDP" } elseif ($logonType -eq 3) { "SMB" } else { "Local" }
        }
    }
} catch {}
Write-Host "  Found: $($failedLogins.Count) failed login attempts" -ForegroundColor White

# ============================================================
# 2. SUCCESSFUL LOGINS (Event 4624)
# ============================================================
Write-Host "[2/10] Collecting successful logins..." -ForegroundColor Yellow
$successLogins = @()
try {
    $events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=(Get-Date).AddDays(-$DaysBack)} -MaxEvents 5000 2>$null
    foreach ($evt in $events) {
        $xml = [xml]$evt.ToXml()
        $data = @{}
        foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }

        $logonType = [int]$data['LogonType']
        if ($logonType -eq 0 -or $logonType -eq 5) { continue }

        $user = $data['TargetUserName']
        if ($user -eq '-' -or $user -eq 'SYSTEM' -or $user -eq 'LOCAL SERVICE' -or
            $user -eq 'NETWORK SERVICE' -or $user -eq 'ANONYMOUS LOGON' -or $user -match '\$$') { continue }

        $ip = $data['IpAddress']
        if ($ip -eq '-' -or $ip -eq '::1' -or $ip -eq '127.0.0.1') { $ip = 'Local' }

        $logonTypeName = switch ($logonType) {
            2  { "Interactive" }
            3  { "Network/SMB" }
            7  { "Unlock" }
            8  { "NetworkCleartext" }
            10 { "RDP" }
            11 { "Cached" }
            default { "Type $logonType" }
        }

        $successLogins += [PSCustomObject]@{
            Time      = $evt.TimeCreated
            Username  = if ($data['TargetDomainName'] -and $data['TargetDomainName'] -ne '-') { "$($data['TargetDomainName'])\$user" } else { $user }
            SourceIP  = $ip
            LogonType = $logonTypeName
            Protocol  = if ($logonType -eq 10) { "RDP" } elseif ($logonType -eq 3) { "SMB" } else { "Local" }
        }
    }
} catch {}
Write-Host "  Found: $($successLogins.Count) successful logins" -ForegroundColor White

# ============================================================
# 3. ACCOUNT LOCKOUTS (Event 4740)
# ============================================================
Write-Host "[3/10] Checking account lockouts..." -ForegroundColor Yellow
$lockouts = @()
try {
    $events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4740; StartTime=(Get-Date).AddDays(-$DaysBack)} -MaxEvents 500 2>$null
    foreach ($evt in $events) {
        $xml = [xml]$evt.ToXml()
        $data = @{}
        foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }
        $lockouts += [PSCustomObject]@{
            Time     = $evt.TimeCreated
            Username = $data['TargetUserName']
            Source   = $data['TargetDomainName']
        }
    }
} catch {}
Write-Host "  Found: $($lockouts.Count) account lockouts" -ForegroundColor White

# ============================================================
# 4. ACCOUNT CHANGES (4720/4726/4732/4733/4723/4724)
# ============================================================
Write-Host "[4/10] Checking account changes..." -ForegroundColor Yellow
$accountChanges = @()
try {
    $events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=@(4720,4726,4732,4733,4723,4724); StartTime=(Get-Date).AddDays(-$DaysBack)} -MaxEvents 500 2>$null
    foreach ($evt in $events) {
        $xml = [xml]$evt.ToXml()
        $data = @{}
        foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }

        $changeType = switch ($evt.Id) {
            4720 { "Account Created" }
            4726 { "Account Deleted" }
            4732 { "Added to Group" }
            4733 { "Removed from Group" }
            4723 { "Password Changed (self)" }
            4724 { "Password Reset (admin)" }
        }

        $accountChanges += [PSCustomObject]@{
            Time       = $evt.TimeCreated
            ChangeType = $changeType
            Target     = $data['TargetUserName']
            PerformedBy = $data['SubjectUserName']
            Group      = if ($evt.Id -in 4732,4733) { $data['TargetUserName'] } else { '' }
        }
    }
} catch {}
Write-Host "  Found: $($accountChanges.Count) account changes" -ForegroundColor White

# ============================================================
# 5. BRUTE FORCE DETECTION
# ============================================================
Write-Host "[5/10] Analyzing brute force patterns..." -ForegroundColor Yellow
$bruteForce = @()
$failedByIP = $failedLogins | Where-Object { $_.SourceIP -ne 'Local' } | Group-Object SourceIP
foreach ($group in $failedByIP) {
    if ($group.Count -ge 5) {
        $firstAttempt = ($group.Group | Sort-Object Time | Select-Object -First 1).Time
        $lastAttempt = ($group.Group | Sort-Object Time | Select-Object -Last 1).Time
        $targetAccounts = ($group.Group | Select-Object -ExpandProperty Username -Unique) -join ', '
        $protocols = ($group.Group | Select-Object -ExpandProperty Protocol -Unique) -join ', '

        $followedBySuccess = $successLogins | Where-Object {
            $_.SourceIP -eq $group.Name -and $_.Time -gt $firstAttempt
        }

        $bruteForce += [PSCustomObject]@{
            SourceIP       = $group.Name
            AttemptCount   = $group.Count
            FirstAttempt   = $firstAttempt
            LastAttempt    = $lastAttempt
            TargetAccounts = $targetAccounts
            Protocols      = $protocols
            Compromised    = if ($followedBySuccess) { "YES - SUCCESSFUL LOGIN AFTER ATTACK" } else { "No" }
            Severity       = if ($followedBySuccess) { "CRITICAL" } elseif ($group.Count -ge 20) { "HIGH" } elseif ($group.Count -ge 10) { "MEDIUM" } else { "LOW" }
        }
    }
}
$bruteForce = $bruteForce | Sort-Object AttemptCount -Descending
Write-Host "  Found: $($bruteForce.Count) brute force sources" -ForegroundColor $(if ($bruteForce.Count -gt 0) { 'Red' } else { 'Green' })

# ============================================================
# 6. NETWORK DEVICE DISCOVERY
# ============================================================
Write-Host "[6/10] Discovering network devices..." -ForegroundColor Yellow
$devices = @()
try {
    $arpOutput = arp -a
    foreach ($line in $arpOutput) {
        if ($line -match '(\d+\.\d+\.\d+\.\d+)\s+([\da-f-]+)\s+(\w+)') {
            $ip = $Matches[1]
            $mac = $Matches[2].ToUpper()
            $type = $Matches[3]

            if ($mac -eq 'FF-FF-FF-FF-FF-FF' -or $ip -match '\.255$' -or $ip -match '\.0$') { continue }

            $hostname = ''
            try { $hostname = [System.Net.Dns]::GetHostEntry($ip).HostName } catch {}

            $vendor = ''
            $prefix = ($mac -replace '-','').Substring(0,6)
            $vendorMap = @{
                'D8BBC1'='Dell'; '001DD8'='Microsoft'; '005056'='VMware'; '000C29'='VMware'
                '00155D'='Hyper-V'; '14B31F'='Dell'; 'F8B156'='Dell'; 'B083FE'='Dell'
                '001635'='HP'; '3C4A92'='HP'; '18A905'='HP'; '94B866'='HP'; '80E82C'='HP'
                '3CA82A'='Intel'; 'A0369F'='Intel'; 'DC536C'='Intel'; 'ECEBB8'='Intel'
                'AC220B'='ASUS'; '60455E'='Apple'; 'A860B6'='Apple'; 'DC2B2A'='Apple'
                'A4CF12'='Cisco'; '001921'='Cisco'; '000C85'='Cisco'; '001BD4'='Cisco'
                '001122'='Synology'; 'EC086B'='TP-Link'; '50C7BF'='TP-Link'
                '001E58'='D-Link'; '00256B'='Netgear'; 'E091F5'='Netgear'
                '34298F'='Lenovo'; '5CF7E6'='Lenovo'; '001CBF'='QNAP'
                '0050F2'='Microsoft'; '4CCC6A'='Dell'; '2C44FD'='HP'
                '48B02D'='NVIDIA'; 'B0BE76'='TP-Link'; 'FCF528'='ZyXEL'
            }
            if ($vendorMap.ContainsKey($prefix)) { $vendor = $vendorMap[$prefix] }

            $devices += [PSCustomObject]@{
                IP       = $ip
                MAC      = $mac
                Hostname = $hostname
                Vendor   = $vendor
                Type     = $type
            }
        }
    }
} catch {}
Write-Host "  Found: $($devices.Count) network devices" -ForegroundColor White

# ============================================================
# 7. OPEN PORTS SCAN
# ============================================================
Write-Host "[7/10] Scanning open ports..." -ForegroundColor Yellow
$openPorts = @()
try {
    $connections = Get-NetTCPConnection -State Listen 2>$null
    $riskyPorts = @{
        21='FTP'; 23='Telnet'; 25='SMTP'; 80='HTTP'; 135='RPC'; 139='NetBIOS'
        443='HTTPS'; 445='SMB'; 1433='SQL Server'; 1434='SQL Browser'
        3306='MySQL'; 3389='RDP'; 5432='PostgreSQL'; 5900='VNC'
        5985='WinRM'; 5986='WinRM-SSL'; 8080='HTTP Proxy'; 8443='Alt HTTPS'
        22='SSH'; 53='DNS'; 88='Kerberos'; 389='LDAP'; 636='LDAPS'
    }

    foreach ($conn in $connections) {
        $port = $conn.LocalPort
        $addr = $conn.LocalAddress
        $processId = $conn.OwningProcess
        $processName = ''
        try { $processName = (Get-Process -Id $processId).ProcessName } catch {}

        $isRisky = $riskyPorts.ContainsKey($port)
        $isExposed = ($addr -eq '0.0.0.0' -or $addr -eq '::')
        $serviceName = if ($riskyPorts.ContainsKey($port)) { $riskyPorts[$port] } else { "Port $port" }

        $risk = 'Low'
        if ($isRisky -and $isExposed) { $risk = 'High' }
        elseif ($isRisky) { $risk = 'Medium' }
        elseif ($isExposed -and $port -lt 1024) { $risk = 'Medium' }

        if ($port -lt 50000) {
            $openPorts += [PSCustomObject]@{
                Port        = $port
                Service     = $serviceName
                Address     = $addr
                Process     = $processName
                PID         = $processId
                Exposed     = $isExposed
                Risk        = $risk
            }
        }
    }
    $openPorts = $openPorts | Sort-Object Port -Unique
} catch {}
Write-Host "  Found: $($openPorts.Count) listening ports" -ForegroundColor White

# ============================================================
# 8. WINDOWS DEFENDER STATUS
# ============================================================
Write-Host "[8/10] Checking security status..." -ForegroundColor Yellow
$defenderStatus = @{}
try {
    $mpStatus = Get-MpComputerStatus 2>$null
    if ($mpStatus) {
        $defenderStatus = @{
            RealTimeProtection  = $mpStatus.RealTimeProtectionEnabled
            AntivirusEnabled    = $mpStatus.AntivirusEnabled
            AntispywareEnabled  = $mpStatus.AntispywareEnabled
            SignatureAge        = $mpStatus.AntivirusSignatureAge
            LastScan            = $mpStatus.QuickScanEndTime
            TamperProtection    = $mpStatus.IsTamperProtected
            BehaviorMonitor     = $mpStatus.BehaviorMonitorEnabled
            CloudProtection     = $mpStatus.MAPSReporting -ne 0
        }
    }
} catch { $defenderStatus = @{ Error = "Unable to query Defender" } }

# Firewall
$firewallStatus = @{}
try {
    $profiles = Get-NetFirewallProfile 2>$null
    foreach ($p in $profiles) {
        $firewallStatus[$p.Name] = $p.Enabled
    }
} catch {}

# BitLocker
$bitlockerStatus = "Not Available"
try {
    $bl = Get-BitLockerVolume -MountPoint "C:" 2>$null
    if ($bl) { $bitlockerStatus = $bl.ProtectionStatus.ToString() }
} catch {}

# Windows Update
$lastUpdate = "Unknown"
try {
    $hotfix = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1
    if ($hotfix) { $lastUpdate = $hotfix.InstalledOn.ToString("yyyy-MM-dd") }
} catch {}

Write-Host "  Security status collected" -ForegroundColor White

# ============================================================
# 9. POWERSHELL ACTIVITY (Event 4104)
# ============================================================
Write-Host "[9/10] Checking PowerShell activity..." -ForegroundColor Yellow
$psActivity = @()
try {
    $events = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104; StartTime=(Get-Date).AddDays(-$DaysBack)} -MaxEvents 200 2>$null
    $suspiciousPatterns = @(
        'Invoke-WebRequest', 'Invoke-Expression', 'IEX', 'DownloadString',
        'DownloadFile', 'Start-BitsTransfer', 'New-Object Net.WebClient',
        'Bypass', 'Hidden', 'EncodedCommand', '-enc ', 'FromBase64',
        'Mimikatz', 'Invoke-Mimikatz', 'sekurlsa', 'kerberos::',
        'Invoke-ReflectivePEInjection', 'Invoke-Shellcode',
        'Set-MpPreference -Disable', 'Add-MpPreference -ExclusionPath',
        'vssadmin delete', 'wbadmin delete', 'bcdedit /set',
        'Invoke-Command -ComputerName', 'Enter-PSSession'
    )

    foreach ($evt in $events) {
        $scriptBlock = $evt.Properties[2].Value.ToString()
        $isSuspicious = $false
        $matchedPattern = ''

        foreach ($pattern in $suspiciousPatterns) {
            if ($scriptBlock -match [regex]::Escape($pattern)) {
                $isSuspicious = $true
                $matchedPattern = $pattern
                break
            }
        }

        if ($isSuspicious) {
            $psActivity += [PSCustomObject]@{
                Time    = $evt.TimeCreated
                Pattern = $matchedPattern
                Script  = if ($scriptBlock.Length -gt 200) { $scriptBlock.Substring(0,200) + '...' } else { $scriptBlock }
            }
        }
    }
} catch {}
Write-Host "  Found: $($psActivity.Count) suspicious PowerShell executions" -ForegroundColor $(if ($psActivity.Count -gt 0) { 'Red' } else { 'Green' })

# ============================================================
# 10. RDP SESSION ANALYSIS
# ============================================================
Write-Host "[10/10] Analyzing RDP sessions..." -ForegroundColor Yellow
$rdpSessions = $successLogins | Where-Object { $_.LogonType -eq 'RDP' -and $_.SourceIP -ne 'Local' }
$rdpFailed = $failedLogins | Where-Object { $_.LogonType -eq 'RDP' -and $_.SourceIP -ne 'Local' }
Write-Host "  RDP: $($rdpSessions.Count) successful, $($rdpFailed.Count) failed" -ForegroundColor White

# ============================================================
# RISK SCORE CALCULATION
# ============================================================
Write-Host "`nCalculating risk score..." -ForegroundColor Cyan
$riskScore = 100
$riskItems = @()

if ($bruteForce.Count -gt 0) {
    $deduct = [Math]::Min($bruteForce.Count * 5, 25)
    $riskScore -= $deduct
    $riskItems += "Brute force attacks detected (-$deduct)"
}
$compromised = $bruteForce | Where-Object { $_.Compromised -match 'YES' }
if ($compromised.Count -gt 0) {
    $riskScore -= 30
    $riskItems += "COMPROMISED ACCOUNTS detected (-30)"
}
if ($lockouts.Count -gt 5) {
    $riskScore -= 10
    $riskItems += "Multiple account lockouts (-10)"
}
if ($psActivity.Count -gt 0) {
    $deduct = [Math]::Min($psActivity.Count * 3, 15)
    $riskScore -= $deduct
    $riskItems += "Suspicious PowerShell activity (-$deduct)"
}
$highRiskPorts = $openPorts | Where-Object { $_.Risk -eq 'High' }
if ($highRiskPorts.Count -gt 0) {
    $deduct = [Math]::Min($highRiskPorts.Count * 5, 20)
    $riskScore -= $deduct
    $riskItems += "High-risk ports exposed (-$deduct)"
}
if (-not $defenderStatus.RealTimeProtection) {
    $riskScore -= 15
    $riskItems += "Real-time protection disabled (-15)"
}
if ($defenderStatus.SignatureAge -gt 7) {
    $riskScore -= 10
    $riskItems += "Antivirus signatures outdated (-10)"
}
if ($firewallStatus.Values -contains $false) {
    $riskScore -= 10
    $riskItems += "Firewall profile(s) disabled (-10)"
}
if ($bitlockerStatus -ne 'On') {
    $riskScore -= 5
    $riskItems += "Drive not encrypted (-5)"
}
if ($rdpFailed.Count -gt 20) {
    $deduct = [Math]::Min(15, [int]($rdpFailed.Count / 5))
    $riskScore -= $deduct
    $riskItems += "High RDP attack volume (-$deduct)"
}
if ($accountChanges | Where-Object { $_.ChangeType -eq 'Account Created' }) {
    $riskScore -= 5
    $riskItems += "New accounts created (-5)"
}

$riskScore = [Math]::Max(0, $riskScore)
$riskGrade = switch ($riskScore) {
    { $_ -ge 90 } { 'A' }
    { $_ -ge 80 } { 'B' }
    { $_ -ge 70 } { 'C' }
    { $_ -ge 60 } { 'D' }
    default { 'F' }
}
$riskColor = switch ($riskScore) {
    { $_ -ge 80 } { '#10b981' }
    { $_ -ge 60 } { '#f59e0b' }
    default { '#ef4444' }
}

Write-Host "Risk Score: $riskScore/100 ($riskGrade)" -ForegroundColor $(if ($riskScore -ge 80) { 'Green' } elseif ($riskScore -ge 60) { 'Yellow' } else { 'Red' })

# ============================================================
# GENERATE HTML REPORT
# ============================================================
Write-Host "`nGenerating report..." -ForegroundColor Cyan

$computerName = $env:COMPUTERNAME
$scanDate = Get-Date -Format "MMMM d, yyyy h:mm tt"
$osInfo = (Get-CimInstance Win32_OperatingSystem).Caption

# Failed logins by hour chart data
$failedByHour = @{}
for ($i = 0; $i -lt 24; $i++) { $failedByHour[$i] = 0 }
foreach ($fl in $failedLogins) { $failedByHour[$fl.Time.Hour]++ }
$maxHourCount = ($failedByHour.Values | Measure-Object -Maximum).Maximum
if ($maxHourCount -eq 0) { $maxHourCount = 1 }

$hourBarsHtml = ""
for ($i = 0; $i -lt 24; $i++) {
    $count = $failedByHour[$i]
    $heightPct = [Math]::Round(($count / $maxHourCount) * 100)
    $barColor = if ($count -gt ($maxHourCount * 0.7)) { '#ef4444' } elseif ($count -gt ($maxHourCount * 0.3)) { '#f59e0b' } else { '#2596be' }
    $label = "{0:00}:00" -f $i
    $hourBarsHtml += "<div style='display:flex;flex-direction:column;align-items:center;flex:1;min-width:20px;'><div style='font-size:9px;color:#5a6b7f;margin-bottom:2px;'>$count</div><div style='width:100%;max-width:24px;height:${heightPct}px;background:$barColor;border-radius:3px 3px 0 0;min-height:2px;'></div><div style='font-size:8px;color:#8d9bb0;margin-top:3px;'>$label</div></div>"
}

# Top attackers table
$topAttackersHtml = ""
$rank = 0
foreach ($attacker in ($bruteForce | Select-Object -First 15)) {
    $rank++
    $sevColor = switch ($attacker.Severity) {
        'CRITICAL' { '#ef4444' }
        'HIGH' { '#f97316' }
        'MEDIUM' { '#f59e0b' }
        default { '#3b82f6' }
    }
    $compBadge = if ($attacker.Compromised -match 'YES') { '<span style="background:#fee2e2;color:#dc2626;padding:1px 6px;border-radius:4px;font-size:9px;font-weight:700;">COMPROMISED</span>' } else { '' }
    $topAttackersHtml += "<tr><td style='font-weight:700;color:$sevColor;'>$rank</td><td style='font-family:monospace;font-weight:600;'>$($attacker.SourceIP)</td><td style='font-weight:700;color:$sevColor;'>$($attacker.AttemptCount)</td><td>$($attacker.Protocols)</td><td style='font-size:11px;'>$($attacker.TargetAccounts)</td><td><span style='background:$(if($sevColor -eq '#ef4444'){'#fee2e2'}elseif($sevColor -eq '#f97316'){'#fff7ed'}elseif($sevColor -eq '#f59e0b'){'#fef3c7'}else{'#dbeafe'});color:$sevColor;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;'>$($attacker.Severity)</span> $compBadge</td></tr>"
}
if ($topAttackersHtml -eq "") { $topAttackersHtml = "<tr><td colspan='6' style='text-align:center;color:#10b981;padding:20px;'>No brute force attacks detected</td></tr>" }

# Devices table
$devicesHtml = ""
foreach ($dev in $devices) {
    $vendorBadge = if ($dev.Vendor) { "<span style='background:#e6f3fa;color:#2596be;padding:1px 6px;border-radius:4px;font-size:9px;font-weight:600;'>$($dev.Vendor)</span>" } else { "<span style='color:#8d9bb0;font-size:10px;'>Unknown</span>" }
    $devicesHtml += "<tr><td style='font-family:monospace;font-weight:600;'>$($dev.IP)</td><td style='font-family:monospace;font-size:11px;'>$($dev.MAC)</td><td>$($dev.Hostname)</td><td>$vendorBadge</td></tr>"
}
if ($devicesHtml -eq "") { $devicesHtml = "<tr><td colspan='4' style='text-align:center;color:#8d9bb0;padding:20px;'>No devices found</td></tr>" }

# Open ports table
$portsHtml = ""
foreach ($port in ($openPorts | Sort-Object @{Expression={switch($_.Risk){'High'{0};'Medium'{1};default{2}}}},Port)) {
    $riskBadge = switch ($port.Risk) {
        'High' { '<span style="background:#fee2e2;color:#dc2626;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;">HIGH</span>' }
        'Medium' { '<span style="background:#fef3c7;color:#d97706;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;">MEDIUM</span>' }
        default { '<span style="background:#f0f3f8;color:#64748b;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:600;">LOW</span>' }
    }
    $exposedIcon = if ($port.Exposed) { '<span style="color:#ef4444;font-weight:700;">EXPOSED</span>' } else { '<span style="color:#10b981;">Local Only</span>' }
    $portsHtml += "<tr><td style='font-weight:700;font-family:monospace;'>$($port.Port)</td><td style='font-weight:600;'>$($port.Service)</td><td>$($port.Process)</td><td>$exposedIcon</td><td>$riskBadge</td></tr>"
}

# Risk items
$riskItemsHtml = ""
foreach ($item in $riskItems) {
    $iconColor = if ($item -match 'COMPROMISED|disabled') { '#ef4444' } elseif ($item -match 'Brute|attack|Suspicious') { '#f59e0b' } else { '#3b82f6' }
    $riskItemsHtml += "<div style='display:flex;align-items:center;gap:8px;padding:8px 12px;background:#f8fafc;border-radius:6px;border-left:3px solid $iconColor;margin-bottom:6px;'><span style='color:$iconColor;font-weight:700;font-size:14px;'>!</span><span style='font-size:12px;color:#334155;'>$item</span></div>"
}
if ($riskItemsHtml -eq "") { $riskItemsHtml = "<div style='padding:20px;text-align:center;color:#10b981;font-weight:600;'>No risk factors detected - excellent security posture!</div>" }

# Account changes table
$accountChangesHtml = ""
foreach ($ac in ($accountChanges | Select-Object -First 20)) {
    $changeColor = switch -Wildcard ($ac.ChangeType) {
        '*Created*' { '#ef4444' }
        '*Deleted*' { '#f59e0b' }
        '*Added*' { '#f97316' }
        '*Removed*' { '#3b82f6' }
        default { '#64748b' }
    }
    $accountChangesHtml += "<tr><td style='font-size:11px;'>$($ac.Time.ToString('MMM d, HH:mm'))</td><td><span style='color:$changeColor;font-weight:600;'>$($ac.ChangeType)</span></td><td style='font-weight:600;'>$($ac.Target)</td><td style='font-size:11px;'>$($ac.PerformedBy)</td></tr>"
}
if ($accountChangesHtml -eq "") { $accountChangesHtml = "<tr><td colspan='4' style='text-align:center;color:#10b981;padding:15px;'>No account changes in the last $DaysBack days</td></tr>" }

# Suspicious PS
$psHtml = ""
foreach ($ps in ($psActivity | Select-Object -First 10)) {
    $psHtml += "<tr><td style='font-size:11px;white-space:nowrap;'>$($ps.Time.ToString('MMM d, HH:mm'))</td><td style='font-weight:600;color:#ef4444;'>$($ps.Pattern)</td><td style='font-size:10px;font-family:monospace;color:#64748b;max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;'>$([System.Web.HttpUtility]::HtmlEncode($ps.Script))</td></tr>"
}

# Security status
$defenderIcon = if ($defenderStatus.RealTimeProtection) { '<span style="color:#10b981;font-weight:700;">ACTIVE</span>' } else { '<span style="color:#ef4444;font-weight:700;">DISABLED</span>' }
$sigAge = if ($defenderStatus.SignatureAge -ne $null) { "$($defenderStatus.SignatureAge) day(s)" } else { "Unknown" }
$sigColor = if ($defenderStatus.SignatureAge -le 3) { '#10b981' } elseif ($defenderStatus.SignatureAge -le 7) { '#f59e0b' } else { '#ef4444' }
$tamperIcon = if ($defenderStatus.TamperProtection) { '<span style="color:#10b981;">Enabled</span>' } else { '<span style="color:#ef4444;">Disabled</span>' }

$fwHtml = ""
foreach ($key in $firewallStatus.Keys) {
    $fwColor = if ($firewallStatus[$key]) { '#10b981' } else { '#ef4444' }
    $fwStatus = if ($firewallStatus[$key]) { 'Enabled' } else { 'DISABLED' }
    $fwHtml += "<div style='display:flex;justify-content:space-between;padding:4px 0;'><span>$key</span><span style='color:$fwColor;font-weight:600;'>$fwStatus</span></div>"
}

$blColor = if ($bitlockerStatus -eq 'On') { '#10b981' } else { '#f59e0b' }

# Recent failed logins table
$recentFailedHtml = ""
foreach ($fl in ($failedLogins | Sort-Object Time -Descending | Select-Object -First 25)) {
    $protocolBadge = switch ($fl.Protocol) {
        'RDP' { '<span style="background:#fee2e2;color:#dc2626;padding:1px 6px;border-radius:4px;font-size:9px;font-weight:700;">RDP</span>' }
        'SMB' { '<span style="background:#fef3c7;color:#d97706;padding:1px 6px;border-radius:4px;font-size:9px;font-weight:700;">SMB</span>' }
        default { '<span style="background:#f0f3f8;color:#64748b;padding:1px 6px;border-radius:4px;font-size:9px;font-weight:600;">LOCAL</span>' }
    }
    $recentFailedHtml += "<tr><td style='font-size:11px;white-space:nowrap;'>$($fl.Time.ToString('MMM d, HH:mm:ss'))</td><td style='font-weight:600;'>$($fl.Username)</td><td style='font-family:monospace;'>$($fl.SourceIP)</td><td>$protocolBadge</td><td style='font-size:11px;color:#64748b;'>$($fl.Reason)</td></tr>"
}

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Network Security Assessment - PC Plus Computing</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800;900&display=swap');
* { margin:0; padding:0; box-sizing:border-box; }
body { font-family:'Plus Jakarta Sans',sans-serif; background:#f0f3f8; color:#1a2332; font-size:13px; line-height:1.5; }
.report-header { background:linear-gradient(135deg, #0a1628 0%, #0f2240 50%, #0a1628 100%); color:#fff; padding:40px; position:relative; overflow:hidden; }
.report-header::before { content:''; position:absolute; top:-50%; right:-20%; width:60%; height:200%; background:radial-gradient(circle, rgba(37,150,190,0.08) 0%, transparent 70%); }
.header-content { position:relative; z-index:1; max-width:1200px; margin:0 auto; display:flex; justify-content:space-between; align-items:center; }
.header-left h1 { font-size:28px; font-weight:900; letter-spacing:-0.5px; margin-bottom:4px; }
.header-left h1 span { color:#2596be; }
.header-left p { color:#94a3b8; font-size:13px; }
.header-left .subtitle { font-size:16px; color:#e2e8f0; font-weight:600; margin-top:12px; }
.header-right { text-align:right; }
.header-right .score-circle { width:120px; height:120px; border-radius:50%; background:conic-gradient($riskColor ${riskScore}%, rgba(255,255,255,0.1) ${riskScore}%); display:flex; align-items:center; justify-content:center; margin:0 auto 8px; }
.header-right .score-inner { width:96px; height:96px; border-radius:50%; background:#0f2240; display:flex; flex-direction:column; align-items:center; justify-content:center; }
.header-right .score-value { font-size:36px; font-weight:900; color:$riskColor; line-height:1; }
.header-right .score-label { font-size:10px; color:#94a3b8; font-weight:600; letter-spacing:1px; text-transform:uppercase; }
.header-right .grade { font-size:14px; font-weight:800; color:$riskColor; margin-top:4px; }
.container { max-width:1200px; margin:0 auto; padding:24px; }
.stats-row { display:grid; grid-template-columns:repeat(auto-fit, minmax(180px,1fr)); gap:16px; margin-bottom:24px; }
.stat-card { background:#fff; border-radius:12px; padding:20px; box-shadow:0 1px 3px rgba(10,22,40,0.06); border:1px solid #e5e9f0; }
.stat-value { font-size:32px; font-weight:900; line-height:1.1; }
.stat-label { font-size:11px; color:#5a6b7f; font-weight:600; text-transform:uppercase; letter-spacing:0.5px; margin-top:4px; }
.card { background:#fff; border-radius:12px; padding:20px; box-shadow:0 1px 3px rgba(10,22,40,0.06); border:1px solid #e5e9f0; margin-bottom:20px; }
.card-title { font-size:15px; font-weight:800; color:#1a2332; display:flex; align-items:center; gap:8px; margin-bottom:16px; }
.card-title .icon { width:28px; height:28px; border-radius:8px; display:flex; align-items:center; justify-content:center; flex-shrink:0; }
table { width:100%; border-collapse:collapse; }
th { text-align:left; padding:8px 12px; background:#f8fafc; color:#5a6b7f; font-size:10px; font-weight:700; text-transform:uppercase; letter-spacing:0.5px; border-bottom:2px solid #e5e9f0; }
td { padding:8px 12px; border-bottom:1px solid #f0f3f8; font-size:12px; vertical-align:middle; }
tr:hover { background:#fafbfc; }
.section-title { font-size:20px; font-weight:800; color:#1a2332; margin:32px 0 16px; display:flex; align-items:center; gap:10px; }
.section-title .dot { width:8px; height:8px; border-radius:50%; }
.two-col { display:grid; grid-template-columns:1fr 1fr; gap:20px; }
.footer { background:#0a1628; color:#94a3b8; padding:30px 40px; text-align:center; margin-top:40px; }
.footer h3 { color:#fff; font-size:16px; margin-bottom:4px; }
.footer a { color:#2596be; text-decoration:none; }
.print-break { page-break-before:always; }
@media print {
    body { background:#fff; }
    .report-header { -webkit-print-color-adjust:exact; print-color-adjust:exact; }
    .card { break-inside:avoid; }
}
@media (max-width:768px) {
    .two-col { grid-template-columns:1fr; }
    .stats-row { grid-template-columns:1fr 1fr; }
    .header-content { flex-direction:column; text-align:center; gap:20px; }
}
</style>
</head>
<body>

<div class="report-header">
  <div class="header-content">
    <div class="header-left">
      <h1>PC Plus <span>Computing</span></h1>
      <p>Network Security Assessment Report</p>
      <div class="subtitle">$computerName - $osInfo</div>
      <p style="margin-top:8px;color:#64748b;font-size:11px;">Generated: $scanDate | Period: Last $DaysBack days</p>
    </div>
    <div class="header-right">
      <div class="score-circle"><div class="score-inner"><div class="score-value">$riskScore</div><div class="score-label">Security Score</div></div></div>
      <div class="grade">Grade: $riskGrade</div>
    </div>
  </div>
</div>

<div class="container">

  <!-- Summary Stats -->
  <div class="stats-row">
    <div class="stat-card"><div class="stat-value" style="color:#ef4444;">$($failedLogins.Count)</div><div class="stat-label">Failed Login Attempts</div></div>
    <div class="stat-card"><div class="stat-value" style="color:#10b981;">$($successLogins.Count)</div><div class="stat-label">Successful Logins</div></div>
    <div class="stat-card"><div class="stat-value" style="color:#f59e0b;">$($bruteForce.Count)</div><div class="stat-label">Brute Force Sources</div></div>
    <div class="stat-card"><div class="stat-value" style="color:#2596be;">$($devices.Count)</div><div class="stat-label">Network Devices</div></div>
    <div class="stat-card"><div class="stat-value" style="color:#8b5cf6;">$($openPorts.Count)</div><div class="stat-label">Open Ports</div></div>
    <div class="stat-card"><div class="stat-value" style="color:$(if($lockouts.Count -gt 0){'#ef4444'}else{'#10b981'});">$($lockouts.Count)</div><div class="stat-label">Account Lockouts</div></div>
  </div>

  <!-- Risk Factors -->
  <div class="card">
    <div class="card-title"><div class="icon" style="background:#fee2e2;"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg></div>Risk Factors</div>
    $riskItemsHtml
  </div>

  <!-- Failed Logins by Hour -->
  <div class="card">
    <div class="card-title"><div class="icon" style="background:#e6f3fa;"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#2596be" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M3 9h18"/><path d="M9 21V9"/></svg></div>Failed Login Attempts by Hour (Last $DaysBack Days)</div>
    <div style="display:flex;align-items:flex-end;gap:2px;height:120px;padding:10px 0;">
      $hourBarsHtml
    </div>
  </div>

  <!-- Brute Force Attacks -->
  <div class="section-title"><div class="dot" style="background:#ef4444;"></div>Brute Force Attack Sources</div>
  <div class="card">
    <table>
      <thead><tr><th>#</th><th>Source IP</th><th>Attempts</th><th>Protocol</th><th>Target Accounts</th><th>Severity</th></tr></thead>
      <tbody>$topAttackersHtml</tbody>
    </table>
  </div>

  <!-- Security Status -->
  <div class="section-title"><div class="dot" style="background:#2596be;"></div>Security Status</div>
  <div class="two-col">
    <div class="card">
      <div class="card-title">Windows Defender</div>
      <div style="display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid #f0f3f8;"><span>Real-Time Protection</span>$defenderIcon</div>
      <div style="display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid #f0f3f8;"><span>Signature Age</span><span style="color:$sigColor;font-weight:600;">$sigAge</span></div>
      <div style="display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid #f0f3f8;"><span>Tamper Protection</span>$tamperIcon</div>
      <div style="display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid #f0f3f8;"><span>Cloud Protection</span><span style="color:$(if($defenderStatus.CloudProtection){'#10b981'}else{'#f59e0b'});font-weight:600;">$(if($defenderStatus.CloudProtection){'Enabled'}else{'Disabled'})</span></div>
      <div style="display:flex;justify-content:space-between;padding:6px 0;"><span>Last Update</span><span style="font-weight:600;">$lastUpdate</span></div>
    </div>
    <div class="card">
      <div class="card-title">Firewall &amp; Encryption</div>
      $fwHtml
      <div style="display:flex;justify-content:space-between;padding:6px 0;margin-top:8px;border-top:1px solid #e5e9f0;"><span style="font-weight:600;">BitLocker Encryption</span><span style="color:$blColor;font-weight:600;">$bitlockerStatus</span></div>
    </div>
  </div>

  <!-- Recent Failed Logins -->
  <div class="section-title"><div class="dot" style="background:#f59e0b;"></div>Recent Failed Login Attempts</div>
  <div class="card">
    <table>
      <thead><tr><th>Time</th><th>Username</th><th>Source IP</th><th>Protocol</th><th>Reason</th></tr></thead>
      <tbody>$recentFailedHtml</tbody>
    </table>
  </div>

  <!-- Account Changes -->
  <div class="section-title"><div class="dot" style="background:#8b5cf6;"></div>Account Changes</div>
  <div class="card">
    <table>
      <thead><tr><th>Time</th><th>Change</th><th>Account</th><th>Performed By</th></tr></thead>
      <tbody>$accountChangesHtml</tbody>
    </table>
  </div>

  <!-- Open Ports -->
  <div class="section-title"><div class="dot" style="background:#3b82f6;"></div>Open Ports &amp; Services</div>
  <div class="card">
    <table>
      <thead><tr><th>Port</th><th>Service</th><th>Process</th><th>Exposure</th><th>Risk</th></tr></thead>
      <tbody>$portsHtml</tbody>
    </table>
  </div>

  <!-- Network Devices -->
  <div class="section-title"><div class="dot" style="background:#10b981;"></div>Discovered Network Devices</div>
  <div class="card">
    <table>
      <thead><tr><th>IP Address</th><th>MAC Address</th><th>Hostname</th><th>Vendor</th></tr></thead>
      <tbody>$devicesHtml</tbody>
    </table>
  </div>

  $(if ($psActivity.Count -gt 0) {
    @"
  <div class="section-title"><div class="dot" style="background:#ef4444;"></div>Suspicious PowerShell Activity</div>
  <div class="card">
    <table>
      <thead><tr><th>Time</th><th>Pattern</th><th>Script Excerpt</th></tr></thead>
      <tbody>$psHtml</tbody>
    </table>
  </div>
"@
  })

  <!-- Recommendations -->
  <div class="section-title"><div class="dot" style="background:#2596be;"></div>Recommendations</div>
  <div class="card">
    <div style="display:grid;gap:12px;">
      $(if ($bruteForce.Count -gt 0) { '<div style="padding:12px 16px;background:#fee2e2;border-radius:8px;border-left:4px solid #ef4444;"><strong style="color:#dc2626;">Block Brute Force Sources</strong><br><span style="font-size:12px;color:#7f1d1d;">Multiple IP addresses are actively attempting to brute-force login credentials. Implement IP blocking, geo-restriction, and multi-factor authentication immediately.</span></div>' })
      $(if ($compromised.Count -gt 0) { '<div style="padding:12px 16px;background:#fee2e2;border-radius:8px;border-left:4px solid #ef4444;"><strong style="color:#dc2626;">CRITICAL: Investigate Compromised Accounts</strong><br><span style="font-size:12px;color:#7f1d1d;">Successful logins detected after brute force attacks. Change all passwords immediately, review access logs, and check for lateral movement.</span></div>' })
      $(if ($highRiskPorts.Count -gt 0) { '<div style="padding:12px 16px;background:#fef3c7;border-radius:8px;border-left:4px solid #f59e0b;"><strong style="color:#92400e;">Close High-Risk Ports</strong><br><span style="font-size:12px;color:#78350f;">Services like RDP, SMB, or SQL Server are exposed to all interfaces. Restrict access via firewall rules or VPN.</span></div>' })
      $(if (-not $defenderStatus.RealTimeProtection) { '<div style="padding:12px 16px;background:#fee2e2;border-radius:8px;border-left:4px solid #ef4444;"><strong style="color:#dc2626;">Enable Real-Time Protection</strong><br><span style="font-size:12px;color:#7f1d1d;">Windows Defender real-time protection is disabled. This leaves the system vulnerable to malware and ransomware.</span></div>' })
      $(if ($bitlockerStatus -ne 'On') { '<div style="padding:12px 16px;background:#fef3c7;border-radius:8px;border-left:4px solid #f59e0b;"><strong style="color:#92400e;">Enable Drive Encryption</strong><br><span style="font-size:12px;color:#78350f;">BitLocker is not active on the system drive. If this device is lost or stolen, all data can be accessed without a password.</span></div>' })
      <div style="padding:12px 16px;background:#e6f3fa;border-radius:8px;border-left:4px solid #2596be;"><strong style="color:#1d7a9c;">Enable Continuous Monitoring</strong><br><span style="font-size:12px;color:#0c4a6e;">Deploy PC Plus Computing Endpoint Protection for 24/7 security monitoring, automated threat detection, brute force blocking, and real-time alerts. Contact us to get started.</span></div>
    </div>
  </div>

</div>

<div class="footer">
  <h3>PC Plus Computing Inc.</h3>
  <p>Your Security Is Our Priority</p>
  <p style="margin-top:8px;">604-760-1662 | 236-500-2700 | <a href="https://pcpluscomputing.com">pcpluscomputing.com</a></p>
  <p style="margin-top:12px;font-size:10px;color:#475569;">This report was generated by the PC Plus Computing Network Security Scanner. &copy; 2026 PC Plus Computing Inc.</p>
</div>

</body>
</html>
"@

$reportPath = Join-Path $OutputDir "report.html"
$html | Out-File -FilePath $reportPath -Encoding UTF8 -Force

# Also save raw data as JSON for the dashboard
$jsonData = @{
    scanDate = (Get-Date -Format "o")
    computerName = $computerName
    osInfo = $osInfo
    daysBack = $DaysBack
    riskScore = $riskScore
    riskGrade = $riskGrade
    summary = @{
        failedLogins = $failedLogins.Count
        successfulLogins = $successLogins.Count
        accountLockouts = $lockouts.Count
        bruteForceAttackers = $bruteForce.Count
        networkDevices = $devices.Count
        openPorts = $openPorts.Count
        suspiciousPowerShell = $psActivity.Count
        rdpSuccessful = $rdpSessions.Count
        rdpFailed = $rdpFailed.Count
        accountChanges = $accountChanges.Count
    }
    bruteForce = $bruteForce | Select-Object SourceIP,AttemptCount,Protocols,TargetAccounts,Severity,Compromised
    riskFactors = $riskItems
} | ConvertTo-Json -Depth 5

$jsonPath = Join-Path $OutputDir "scan_results.json"
$jsonData | Out-File -FilePath $jsonPath -Encoding UTF8 -Force

Write-Host "`n=== SCAN COMPLETE ===" -ForegroundColor Green
Write-Host "Risk Score: $riskScore/100 ($riskGrade)" -ForegroundColor $(if ($riskScore -ge 80) { 'Green' } elseif ($riskScore -ge 60) { 'Yellow' } else { 'Red' })
Write-Host "Report: $reportPath" -ForegroundColor Cyan
Write-Host "Data:   $jsonPath" -ForegroundColor Cyan

if ($OpenReport) {
    Start-Process $reportPath
}
