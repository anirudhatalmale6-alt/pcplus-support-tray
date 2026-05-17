$ErrorActionPreference = "Continue"
$ConfigFile = "$env:ProgramData\PCPlusEndpoint\config.json"
$LogFile = "$env:ProgramData\PCPlusEndpoint\Logs\heartbeat.log"
$ScanCacheFile = "$env:ProgramData\PCPlusEndpoint\scan-cache.json"

if (-not (Test-Path $ConfigFile)) { exit 0 }

try {
    $cfg = Get-Content $ConfigFile -Raw | ConvertFrom-Json
    $dashUrl = $cfg.dashboardApiUrl
    $devId = $cfg.deviceId
    if (-not $dashUrl -or -not $devId) { exit 0 }

    # ── HEALTH DATA (every heartbeat) ──
    $cpu = 0; $ram = 0; $disk = 0
    try {
        $cpu = [math]::Round((Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average, 1)
        $os = Get-CimInstance Win32_OperatingSystem
        $ram = [math]::Round(($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / $os.TotalVisibleMemorySize * 100, 1)
        $c = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
        $disk = [math]::Round(($c.Size - $c.FreeSpace) / $c.Size * 100, 1)
    } catch {}

    $cpuTemp = 0; $gpuTemp = 0
    try {
        $tz = Get-CimInstance -Namespace root/wmi -ClassName MSAcpi_ThermalZoneTemperature -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($tz) { $cpuTemp = [math]::Round($tz.CurrentTemperature / 10 - 273.15, 1) }
        if ($cpuTemp -le 0 -or $cpuTemp -ge 120) { $cpuTemp = 0 }
    } catch {}

    $osVer = "Windows"
    try {
        $build = [Environment]::OSVersion.Version.Build
        if ($build -ge 22000) { $osVer = "Windows 11 (Build $build)" } else { $osVer = "Windows 10 (Build $build)" }
    } catch {}

    $localIp = "0.0.0.0"
    try { $localIp = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -ne "127.0.0.1" -and $_.PrefixOrigin -ne "WellKnown" } | Select-Object -First 1).IPAddress } catch {}

    $svcStatus = try { (Get-Service PCPlusEndpoint -ErrorAction SilentlyContinue).Status.ToString() } catch { "Unknown" }
    $wazuhStatus = try { (Get-Service WazuhSvc -ErrorAction SilentlyContinue).Status.ToString() } catch { "NotInstalled" }

    $custName = if ($cfg.companyName) { $cfg.companyName } else { "" }

    # ── SECURITY SCAN (cached, non-critical - runs every 12 hours) ──
    $scanCacheTtlMinutes = 720
    if ($cfg.securityScanIntervalMinutes) { $scanCacheTtlMinutes = [int]$cfg.securityScanIntervalMinutes }
    $runScan = $true
    $securityChecks = @()
    $securityScore = 0
    $securityGrade = "?"
    $softwareList = @()

    if (Test-Path $ScanCacheFile) {
        try {
            $cache = Get-Content $ScanCacheFile -Raw | ConvertFrom-Json
            $cacheAge = (Get-Date) - [DateTime]$cache.timestamp
            if ($cacheAge.TotalMinutes -lt $scanCacheTtlMinutes) {
                $runScan = $false
                $securityChecks = $cache.checks
                $securityScore = $cache.score
                $securityGrade = $cache.grade
                $softwareList = $cache.software
            }
        } catch { $runScan = $true }
    }

    if ($runScan) {
        $checks = [System.Collections.ArrayList]@()

        # AV check
        try {
            $av = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue
            if ($av) {
                $activeAv = $av | Where-Object { ($_.productState -band 0x1000) -ne 0 } | Select-Object -First 1
                $avName = if ($activeAv) { $activeAv.displayName } else { $av[0].displayName }
                [void]$checks.Add(@{ Id="antivirus"; Name="Antivirus Protection"; Category="Protection"; Passed=$($null -ne $activeAv); Detail="Active: $avName"; Recommendation=""; Weight=15 })
            } else {
                [void]$checks.Add(@{ Id="antivirus"; Name="Antivirus Protection"; Category="Protection"; Passed=$false; Detail="No antivirus detected"; Recommendation="Install antivirus software"; Weight=15 })
            }
        } catch {
            [void]$checks.Add(@{ Id="antivirus"; Name="Antivirus Protection"; Category="Protection"; Passed=$false; Detail="Unable to check"; Recommendation=""; Weight=15 })
        }

        # Firewall
        try {
            $fw = Get-NetFirewallProfile -ErrorAction SilentlyContinue
            $fwEnabled = ($fw | Where-Object { $_.Enabled }).Count
            $fwTotal = ($fw | Measure-Object).Count
            [void]$checks.Add(@{ Id="firewall"; Name="Windows Firewall"; Category="Protection"; Passed=$($fwEnabled -eq $fwTotal); Detail="Firewall enabled on $fwEnabled/$fwTotal profiles"; Recommendation=""; Weight=15 })
        } catch {
            [void]$checks.Add(@{ Id="firewall"; Name="Windows Firewall"; Category="Protection"; Passed=$false; Detail="Unable to check"; Recommendation=""; Weight=15 })
        }

        # Defender RT
        try {
            $def = Get-MpPreference -ErrorAction SilentlyContinue
            $rtEnabled = if ($def) { -not $def.DisableRealtimeMonitoring } else { $false }
            [void]$checks.Add(@{ Id="defender_rt"; Name="Real-time Protection"; Category="Protection"; Passed=$rtEnabled; Detail=$(if ($rtEnabled) {"Real-time protection active"} else {"Real-time protection disabled"}); Recommendation=""; Weight=5 })
        } catch {
            [void]$checks.Add(@{ Id="defender_rt"; Name="Real-time Protection"; Category="Protection"; Passed=$false; Detail="Unable to check"; Recommendation=""; Weight=5 })
        }

        # UAC
        try {
            $uac = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue).EnableLUA
            [void]$checks.Add(@{ Id="uac"; Name="User Account Control"; Category="Protection"; Passed=$($uac -eq 1); Detail=$(if ($uac -eq 1) {"UAC enabled"} else {"UAC disabled"}); Recommendation=""; Weight=10 })
        } catch {}

        # BitLocker
        try {
            $bl = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
            $blOn = $bl -and $bl.ProtectionStatus -eq "On"
            [void]$checks.Add(@{ Id="bitlocker"; Name="BitLocker Encryption"; Category="Encryption"; Passed=$blOn; Detail=$(if ($blOn) {"C: drive encrypted"} else {"C: drive not encrypted"}); Recommendation="Enable BitLocker on system drive"; Weight=10 })
        } catch {
            [void]$checks.Add(@{ Id="bitlocker"; Name="BitLocker Encryption"; Category="Encryption"; Passed=$false; Detail="Unable to check BitLocker"; Recommendation=""; Weight=10 })
        }

        # Windows Update
        try {
            $upd = Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending | Select-Object -First 1
            $daysSince = if ($upd -and $upd.InstalledOn) { ((Get-Date) - $upd.InstalledOn).Days } else { 999 }
            [void]$checks.Add(@{ Id="windows_update"; Name="Windows Updates"; Category="Patching"; Passed=$($daysSince -le 30); Detail="Last update: $daysSince days ago"; Recommendation="Install latest Windows updates"; Weight=10 })
        } catch {}

        # AutoLogin
        try {
            $al = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction SilentlyContinue).AutoAdminLogon
            [void]$checks.Add(@{ Id="autologin"; Name="Auto-Login"; Category="Access"; Passed=$($al -ne "1"); Detail=$(if ($al -eq "1") {"Auto-login configured - security risk"} else {"Auto-login not configured"}); Recommendation="Disable auto-login"; Weight=5 })
        } catch {}

        # Guest Account
        try {
            $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
            [void]$checks.Add(@{ Id="guest"; Name="Guest Account"; Category="Access"; Passed=$($guest -and -not $guest.Enabled); Detail=$(if ($guest -and -not $guest.Enabled) {"Guest account disabled"} else {"Guest account enabled"}); Recommendation="Disable guest account"; Weight=5 })
        } catch {}

        # RDP
        try {
            $rdp = (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -ErrorAction SilentlyContinue).fDenyTSConnections
            $rdpEnabled = ($rdp -eq 0)
            $nla = (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -ErrorAction SilentlyContinue).UserAuthentication
            [void]$checks.Add(@{ Id="rdp"; Name="Remote Desktop"; Category="Network"; Passed=$(-not $rdpEnabled -or $nla -eq 1); Detail=$(if (-not $rdpEnabled) {"RDP disabled"} else { if ($nla -eq 1) {"RDP enabled with NLA"} else {"RDP enabled without NLA - security risk"} }); Recommendation="Enable NLA for RDP"; Weight=10 })
        } catch {}

        # Password Policy
        try {
            $netAcc = net accounts 2>&1
            $minLen = ($netAcc | Select-String "Minimum password length").ToString() -replace "\D",""
            if ($minLen) {
                [void]$checks.Add(@{ Id="password_length"; Name="Password Length Policy"; Category="Access"; Passed=$([int]$minLen -ge 8); Detail="Minimum length: $minLen characters"; Recommendation="Set minimum password length to 8+"; Weight=5 })
            }
        } catch {}

        # Screen Lock
        try {
            $sl = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue).InactivityTimeoutSecs
            [void]$checks.Add(@{ Id="screen_lock"; Name="Screen Lock Timeout"; Category="Protection"; Passed=$($sl -and $sl -le 600); Detail=$(if ($sl) {"Lock after $([math]::Round($sl/60)) minutes"} else {"No lock timeout configured"}); Recommendation="Set screen lock to 10 minutes or less"; Weight=5 })
        } catch {}

        # Controlled Folder Access
        try {
            $cfa = (Get-MpPreference -ErrorAction SilentlyContinue).EnableControlledFolderAccess
            [void]$checks.Add(@{ Id="cfa"; Name="Controlled Folder Access"; Category="Ransomware Protection"; Passed=$($cfa -eq 1); Detail=$(if ($cfa -eq 1) {"Controlled folder access enabled"} else {"Controlled folder access disabled"}); Recommendation="Enable CFA for ransomware protection"; Weight=10 })
        } catch {}

        # SMBv1
        try {
            $smb1 = (Get-SmbServerConfiguration -ErrorAction SilentlyContinue).EnableSMB1Protocol
            [void]$checks.Add(@{ Id="smbv1"; Name="SMBv1 Protocol"; Category="Network"; Passed=$(-not $smb1); Detail=$(if ($smb1) {"SMBv1 enabled - vulnerability risk"} else {"SMBv1 disabled"}); Recommendation="Disable SMBv1"; Weight=10 })
        } catch {}

        # PowerShell Logging
        try {
            $psLog = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue).EnableScriptBlockLogging
            [void]$checks.Add(@{ Id="ps_logging"; Name="PowerShell Logging"; Category="Logging"; Passed=$($psLog -eq 1); Detail=$(if ($psLog -eq 1) {"Script block logging enabled"} else {"Script block logging disabled"}); Recommendation="Enable PowerShell script block logging"; Weight=5 })
        } catch {}

        # Calculate score
        $totalWeight = 0; $passedWeight = 0
        foreach ($ch in $checks) {
            $totalWeight += $ch.Weight
            if ($ch.Passed) { $passedWeight += $ch.Weight }
        }
        $securityScore = if ($totalWeight -gt 0) { [math]::Round($passedWeight / $totalWeight * 100) } else { 0 }
        $securityGrade = if ($securityScore -ge 90) {"A"} elseif ($securityScore -ge 80) {"B+"} elseif ($securityScore -ge 70) {"B"} elseif ($securityScore -ge 60) {"C+"} elseif ($securityScore -ge 50) {"C"} elseif ($securityScore -ge 40) {"D"} else {"F"}
        $securityChecks = $checks

        # Software inventory
        try {
            $rawSw = Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -and $_.DisplayName -is [string] }
            $softwareList = @()
            foreach ($sw in $rawSw) {
                $n = "" + $sw.DisplayName
                $v = "" + $sw.DisplayVersion
                $p = "" + $sw.Publisher
                $d = "" + $sw.InstallDate
                $softwareList += @{ name=$n; version=$v; publisher=$p; installDate=$d; isOutdated=$false }
            }
        } catch { $softwareList = @() }

        # Cache results
        try {
            @{ timestamp=(Get-Date).ToString("o"); checks=$checks; score=$securityScore; grade=$securityGrade; software=$softwareList } | ConvertTo-Json -Depth 5 | Set-Content $ScanCacheFile -Encoding UTF8
        } catch {}
    }

    # ── NETWORK DATA (cached 10 minutes - non-critical) ──
    $NetCacheFile = "$env:ProgramData\PCPlusEndpoint\net-cache.json"
    $runNetScan = $true
    $firewallProfiles = @(); $openPorts = @(); $rdpEnabled = $false; $dnsServers = @(); $activeConn = 0

    if (Test-Path $NetCacheFile) {
        try {
            $netCache = Get-Content $NetCacheFile -Raw | ConvertFrom-Json
            if (((Get-Date) - [DateTime]$netCache.timestamp).TotalMinutes -lt 10) {
                $runNetScan = $false
                $firewallProfiles = $netCache.firewallProfiles
                $openPorts = $netCache.openPorts
                $rdpEnabled = $netCache.rdpEnabled
                $dnsServers = $netCache.dnsServers
                $activeConn = $netCache.activeConn
            }
        } catch { $runNetScan = $true }
    }

    if ($runNetScan) {
        try {
            $firewallProfiles = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue | ForEach-Object { @{ Name=$_.Name; Enabled=[bool]$_.Enabled } })
        } catch {}

        try {
            $openPorts = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Sort-Object LocalPort -Unique | ForEach-Object { @{ Port=[int]$_.LocalPort } } | Select-Object -First 20)
        } catch {}

        try {
            $rdpReg = (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -ErrorAction SilentlyContinue).fDenyTSConnections
            $rdpEnabled = ($rdpReg -eq 0)
        } catch {}

        try {
            $dnsServers = (Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.ServerAddresses } | Select-Object -First 1).ServerAddresses
        } catch {}

        try {
            $activeConn = (Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Measure-Object).Count
        } catch {}

        try {
            @{ timestamp=(Get-Date).ToString("o"); firewallProfiles=$firewallProfiles; openPorts=$openPorts; rdpEnabled=$rdpEnabled; dnsServers=$dnsServers; activeConn=$activeConn } | ConvertTo-Json -Depth 3 | Set-Content $NetCacheFile -Encoding UTF8
        } catch {}
    }

    # ── BITLOCKER KEYS ──
    $bitlockerKeys = @()
    try {
        $bl = Get-BitLockerVolume -ErrorAction SilentlyContinue
        foreach ($vol in $bl) {
            foreach ($kp in $vol.KeyProtector) {
                if ($kp.RecoveryPassword) {
                    $bitlockerKeys += @{ DriveLetter=$vol.MountPoint; KeyProtectorId=$kp.KeyProtectorId; RecoveryKey=$kp.RecoveryPassword }
                }
            }
        }
    } catch {}

    # ── MAC ADDRESS ──
    $mac = ""
    try { $mac = (Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object -First 1).MacAddress } catch {}

    # ── PUBLIC IP ──
    $publicIp = ""
    try { $publicIp = (Invoke-RestMethod -Uri "https://api.ipify.org" -TimeoutSec 3 -ErrorAction SilentlyContinue).Trim() } catch {}

    # ── AGENT VERSION ──
    $agentVer = "4.23.0"
    try {
        $svcExe = Get-Item "$env:ProgramFiles\PC Plus\Endpoint Protection\Service\PCPlusService.exe" -ErrorAction SilentlyContinue
        if ($svcExe) { $agentVer = $svcExe.VersionInfo.ProductVersion }
    } catch {}

    # ── BUILD PAYLOAD ──
    $tier = "Free"
    if ($cfg.activeTier) { $tier = [string]$cfg.activeTier }
    $grp = ""
    if ($cfg.deviceGroup) { $grp = [string]$cfg.deviceGroup }
    $runMods = 0
    if ($svcStatus -eq "Running") { $runMods++ }
    if ($wazuhStatus -eq "Running") { $runMods++ }
    $fwEnabled = $false
    foreach ($fp in $firewallProfiles) { if ($fp.Enabled) { $fwEnabled = $true; break } }
    $dnsArr = @()
    if ($dnsServers) { foreach ($d in $dnsServers) { $dnsArr += [string]$d } }

    $body = @{
        deviceId = [string]$devId
        hostname = [string]$env:COMPUTERNAME
        osVersion = [string]$osVer
        agentVersion = [string]$agentVer
        licenseTier = $tier
        customerName = [string]$custName
        localIp = [string]$localIp
        publicIp = [string]$publicIp
        macAddress = [string]$mac
        cpuPercent = [float]$cpu
        ramPercent = [float]$ram
        diskPercent = [float]$disk
        cpuTempC = [float]$cpuTemp
        gpuTempC = [float]$gpuTemp
        securityScore = [int]$securityScore
        securityGrade = [string]$securityGrade
        securityChecks = @($securityChecks)
        bitLockerRecoveryKeys = @($bitlockerKeys)
        lockdownActive = $false
        activeAlerts = 0
        runningModules = $runMods
        deviceGroup = $grp
        networkData = @{
            firewallEnabled = $fwEnabled
            firewallProfiles = @($firewallProfiles)
            openPorts = @($openPorts)
            activeConnections = [int]$activeConn
            rdpEnabled = [bool]$rdpEnabled
            dnsServers = $dnsArr
        }
    } | ConvertTo-Json -Depth 5 -Compress

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-RestMethod -Uri "$dashUrl/api/endpoint/heartbeat" -Method POST -ContentType "application/json" -Body $body -TimeoutSec 10 | Out-Null

    # Report AV products
    try {
        $avProds = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue
        if ($avProds) {
            $prodList = @()
            foreach ($p in $avProds) {
                $state = $p.productState
                $rtOn = ($state -band 0x1000) -ne 0
                $status = if ($rtOn) { "Active" } else { "Passive" }
                $prodList += @{
                    name = [string]$p.displayName
                    vendor = [string]$p.displayName.Split(' ')[0]
                    version = ""
                    status = $status
                    realTimeEnabled = $rtOn
                    quarantineCount = 0
                }
            }
            $avBody = @{
                deviceId = [string]$devId
                hostname = [string]$env:COMPUTERNAME
                products = $prodList
            } | ConvertTo-Json -Depth 4 -Compress
            Invoke-RestMethod -Uri "$dashUrl/api/endpoint/antivirus" -Method POST -ContentType "application/json" -Body $avBody -TimeoutSec 10 | Out-Null
        }
    } catch {}

    # Forward queued alerts
    $queueDir = "$env:ProgramData\PCPlusEndpoint\alert-queue"
    if (Test-Path $queueDir) {
        $alertFiles = Get-ChildItem $queueDir -Filter "*.json" -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -First 5
        foreach ($af in $alertFiles) {
            try {
                $alertJson = Get-Content $af.FullName -Raw
                Invoke-RestMethod -Uri "$dashUrl/api/endpoint/alert" -Method POST -ContentType "application/json" -Body $alertJson -TimeoutSec 10 | Out-Null
                Remove-Item $af.FullName -Force
            } catch {}
        }
    }

    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') OK cpu=$cpu ram=$ram disk=$disk score=$securityScore grade=$securityGrade checks=$($securityChecks.Count)" | Set-Content $LogFile -Encoding UTF8
} catch {
    $errMsg = $_.Exception.Message
    $errBody = ""
    try {
        if ($_.Exception.Response) {
            $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
            $errBody = $reader.ReadToEnd()
            $reader.Close()
        }
    } catch {}
    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') FAIL: $errMsg | $errBody" | Set-Content $LogFile -Encoding UTF8
}
