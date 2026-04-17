using System.Diagnostics;
using System.Management;
using System.ServiceProcess;
using Microsoft.Win32;
using PCPlus.Core.Interfaces;
using PCPlus.Core.Models;

namespace PCPlus.Service.Modules.Security
{
    /// <summary>
    /// Security scanner module. Runs 11-point security audit.
    /// Produces 0-100 score with grade. Detects AV off, firewall changes.
    /// Free tier for basic, Standard+ for continuous monitoring.
    /// </summary>
    public class SecurityModule : IModule
    {
        public string Id => "security";
        public string Name => "Security Scanner";
        public string Version => "4.0.0";
        public LicenseTier RequiredTier => LicenseTier.Free;
        public bool IsRunning { get; private set; }

        private IModuleContext _context = null!;
        private SecurityScanResult _lastResult = new();
        private Timer? _periodicScan;
        private bool _avWasActive = true;

        public Task InitializeAsync(IModuleContext context)
        {
            _context = context;
            return Task.CompletedTask;
        }

        public Task StartAsync(CancellationToken cancellationToken)
        {
            IsRunning = true;
            // Run initial scan
            Task.Run(() => RunFullScan());
            // Periodic rescan every 30 minutes
            _periodicScan = new Timer(_ => RunFullScan(), null,
                TimeSpan.FromMinutes(30), TimeSpan.FromMinutes(30));
            return Task.CompletedTask;
        }

        public Task StopAsync()
        {
            _periodicScan?.Dispose();
            IsRunning = false;
            return Task.CompletedTask;
        }

        public Task<ModuleResponse> HandleCommandAsync(ModuleCommand command)
        {
            switch (command.Action)
            {
                case "GetSecurityScore":
                case "GetSecurityReport":
                    return Task.FromResult(ModuleResponse.Ok("", new Dictionary<string, object>
                    {
                        ["result"] = _lastResult
                    }));

                case "RunSecurityScan":
                    RunFullScan();
                    return Task.FromResult(ModuleResponse.Ok("Scan complete", new Dictionary<string, object>
                    {
                        ["result"] = _lastResult
                    }));

                case "Remediate":
                    var checkId = command.Parameters?.GetValueOrDefault("checkId") ?? "";
                    var result = ExecuteRemediation(checkId);
                    // Re-scan after remediation to update scores
                    if (result.Success) RunFullScan();
                    return Task.FromResult(result);

                default:
                    return Task.FromResult(ModuleResponse.Fail($"Unknown: {command.Action}"));
            }
        }

        private ModuleResponse ExecuteRemediation(string checkId)
        {
            try
            {
                var (success, message) = checkId switch
                {
                    "cfa" => RunPowerShell("Set-MpPreference -EnableControlledFolderAccess Enabled", "Controlled Folder Access"),
                    "tamper_protect" => (false, "Tamper Protection must be enabled manually in Windows Security settings"),
                    "defender_rt" => RunPowerShell("Set-MpPreference -DisableRealtimeMonitoring $false", "Real-time Protection"),
                    "firewall" => RunPowerShell("Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True", "Windows Firewall"),
                    "rdp" => RunPowerShell("Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' -Name 'fDenyTSConnections' -Value 1", "RDP Disabled"),
                    "rdp_exposure" => RunPowerShell("Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name 'SecurityLayer' -Value 2; Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name 'UserAuthentication' -Value 1", "RDP NLA Enabled"),
                    "smbv1" => RunPowerShell("Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force", "SMBv1 Disabled"),
                    "uac" => RunPowerShell("Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'EnableLUA' -Value 1", "UAC Enabled"),
                    "ps_logging" => RunPowerShell(@"
                        New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Force | Out-Null;
                        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Value 1;
                        New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -Force | Out-Null;
                        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -Name 'EnableModuleLogging' -Value 1;
                        New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Force | Out-Null;
                        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Name 'EnableTranscripting' -Value 1", "PowerShell Logging"),
                    "ps_exec_policy" => RunPowerShell("Set-ExecutionPolicy RemoteSigned -Force -Scope LocalMachine", "Script Execution Policy"),
                    "guest" => RunPowerShell("net user Guest /active:no", "Guest Account Disabled"),
                    "autologin" => RunPowerShell("Remove-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -Name 'DefaultPassword' -ErrorAction SilentlyContinue; Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -Name 'AutoAdminLogon' -Value '0'", "Auto-Login Disabled"),
                    "shadow_copies" => RunPowerShell("Enable-ComputerRestore -Drive 'C:\\'; vssadmin create shadow /for=C:", "Shadow Copies Enabled"),
                    "asr_rules" => RunPowerShell(@"
                        $rules = @(
                            'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550',  # Block executable content from email
                            'D4F940AB-401B-4EFC-AADC-AD5F3C50688A',  # Block Office apps creating child processes
                            '3B576869-A4EC-4529-8536-B80A7769E899',  # Block Office apps creating executables
                            '75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84',  # Block Office apps injecting into processes
                            'D3E037E1-3EB8-44C8-A917-57927947596D',  # Block JavaScript/VBScript launching executables
                            '5BEB7EFE-FD9A-4556-801D-275E5FFC04CC',  # Block execution of potentially obfuscated scripts
                            'E6DB77E5-3DF2-4CF1-B95A-636979351E5B',  # Block persistence through WMI event subscription
                            'B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4',  # Block untrusted/unsigned processes from USB
                            '92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B',  # Block Win32 API calls from Office macros
                            '01443614-CD74-433A-B99E-2ECDC07BFC25'   # Block credential stealing from LSASS
                        );
                        foreach ($rule in $rules) { Add-MpPreference -AttackSurfaceReductionRules_Ids $rule -AttackSurfaceReductionRules_Actions Enabled }", "ASR Rules Enabled"),
                    "lsass_protect" => RunPowerShell("Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'RunAsPPL' -Value 1 -Type DWord", "LSASS Protection (requires reboot)"),
                    "dns_security" => RunPowerShell("Set-DnsClientServerAddress -InterfaceAlias (Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object -First 1 -ExpandProperty Name) -ServerAddresses ('9.9.9.9','149.112.112.112')", "Secure DNS (Quad9)"),
                    "bitlocker" => (false, "BitLocker requires manual setup - run 'manage-bde -on C:' from admin command prompt or use Control Panel"),
                    "backup" => (false, "Backup configuration requires manual setup - enable File History in Windows Settings > Update & Security > Backup"),
                    "edr" => (false, "EDR deployment requires manual installation of your chosen EDR product"),
                    "secure_boot" => (false, "Secure Boot must be enabled in BIOS/UEFI settings - requires physical access"),
                    _ => (false, $"No automatic remediation available for check '{checkId}'")
                };

                _context.Log(success ? LogLevel.Info : LogLevel.Warning, Id,
                    $"Remediation '{checkId}': {(success ? "SUCCESS" : "FAILED")} - {message}");

                return success
                    ? ModuleResponse.Ok(message)
                    : ModuleResponse.Fail(message);
            }
            catch (Exception ex)
            {
                return ModuleResponse.Fail($"Remediation error: {ex.Message}");
            }
        }

        private (bool success, string message) RunPowerShell(string script, string description)
        {
            try
            {
                var startInfo = new ProcessStartInfo("powershell", $"-NoProfile -NonInteractive -Command \"{script.Replace("\"", "\\\"")}\"")
                {
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using var proc = Process.Start(startInfo);
                var output = proc?.StandardOutput.ReadToEnd() ?? "";
                var error = proc?.StandardError.ReadToEnd() ?? "";
                proc?.WaitForExit(30000);

                if (proc?.ExitCode == 0)
                    return (true, $"{description} applied successfully");
                return (false, $"{description} failed: {(string.IsNullOrEmpty(error) ? output : error).Trim()}");
            }
            catch (Exception ex)
            {
                return (false, $"{description} error: {ex.Message}");
            }
        }

        public ModuleStatus GetStatus() => new()
        {
            ModuleId = Id,
            ModuleName = Name,
            IsRunning = IsRunning,
            RequiredTier = RequiredTier,
            StatusText = $"Score: {_lastResult.TotalScore}/100 ({_lastResult.Grade})",
            LastActivity = _lastResult.ScanTime,
            Metrics = new()
            {
                ["score"] = _lastResult.TotalScore,
                ["grade"] = _lastResult.Grade,
                ["passedChecks"] = _lastResult.Checks.Count(c => c.Passed),
                ["totalChecks"] = _lastResult.Checks.Count
            }
        };

        private void RunFullScan()
        {
            var checks = new List<SecurityCheck>
            {
                // === PROTECTION ===
                CheckAntivirus(),
                CheckFirewall(),
                CheckDefenderRealtime(),
                CheckUAC(),
                CheckExploitProtection(),
                CheckControlledFolderAccess(),
                CheckTamperProtection(),
                CheckCredentialGuard(),
                CheckLsassProtection(),

                // === IDENTITY & ACCESS ===
                CheckGuestAccount(),
                CheckAutoLogin(),
                CheckAdminAccountCount(),
                CheckPasswordPolicy(),
                CheckInactiveUsers(),
                CheckPrivilegeEscalation(),

                // === NETWORK ===
                CheckRDP(),
                CheckRdpExposure(),
                CheckSMBv1(),
                CheckOpenPorts(),
                CheckDnsSecurity(),
                CheckWifiSecurity(),
                CheckVpnStatus(),

                // === UPDATES & PATCHES ===
                CheckWindowsUpdate(),
                CheckLastWindowsUpdate(),
                CheckWindowsVersion(),
                CheckEndOfLifeSoftware(),
                CheckOutdatedSoftware(),
                CheckMissingCriticalUpdates(),

                // === DATA PROTECTION ===
                CheckBitLocker(),
                CheckBackupStatus(),
                CheckShadowCopies(),
                CheckBackupFrequency(),
                CheckFolderProtection(),

                // === DEVICE HEALTH ===
                CheckDiskSmartHealth(),
                CheckSsdWearLevel(),
                CheckBatteryHealth(),
                CheckRamErrors(),

                // === EDR & ADVANCED ===
                CheckEdrInstalled(),
                CheckPowerShellLogging(),
                CheckScriptExecutionPolicy(),
                CheckSecureBoot(),
                CheckAttackSurfaceReduction(),
                CheckSuspiciousScheduledTasks()
            };

            var totalWeight = checks.Sum(c => c.Weight);
            var earnedWeight = checks.Where(c => c.Passed).Sum(c => c.Weight);
            var score = totalWeight > 0 ? (int)Math.Round((double)earnedWeight / totalWeight * 100) : 0;
            var grade = score switch { >= 90 => "A", >= 80 => "B", >= 70 => "C", >= 60 => "D", _ => "F" };

            _lastResult = new SecurityScanResult
            {
                TotalScore = score,
                Grade = grade,
                Checks = checks,
                ScanTime = DateTime.UtcNow
            };

            _context.Log(LogLevel.Info, Id, $"Security scan: {score}/100 ({grade})");

            // Check for AV state changes
            var avCheck = checks.FirstOrDefault(c => c.Id == "antivirus");
            if (avCheck != null)
            {
                if (_avWasActive && !avCheck.Passed)
                {
                    _context.RaiseAlert(new Alert
                    {
                        ModuleId = Id,
                        Title = "Antivirus Disabled",
                        Message = "Antivirus protection is no longer active!",
                        Severity = AlertSeverity.Critical,
                        Category = "security"
                    });
                }
                _avWasActive = avCheck.Passed;
            }

            // Broadcast scan complete event
            _ = _context.BroadcastEventAsync(new ModuleEvent
            {
                SourceModule = Id,
                EventType = ModuleEvent.SECURITY_SCAN_COMPLETE,
                Data = new() { ["score"] = score, ["grade"] = grade }
            });
        }

        // --- Security Checks (each returns pass/fail with weight) ---

        private SecurityCheck CheckWindowsUpdate() => RunCheck("windows_update", "Windows Update", "Updates", 15, () =>
        {
            try
            {
                using var sc = new ServiceController("wuauserv");
                var ok = sc.Status == ServiceControllerStatus.Running || sc.StartType != ServiceStartMode.Disabled;
                return (ok, ok ? "Windows Update service is available" : "Windows Update DISABLED", ok ? "" : "Enable Windows Update");
            }
            catch { return (true, "Unable to check", ""); }
        });

        private SecurityCheck CheckAntivirus() => RunCheck("antivirus", "Antivirus Protection", "Protection", 15, () =>
        {
            try
            {
                using var searcher = new ManagementObjectSearcher("root\\SecurityCenter2",
                    "SELECT displayName, productState FROM AntiVirusProduct");
                var active = new List<string>();
                foreach (ManagementObject obj in searcher.Get())
                {
                    var name = obj["displayName"]?.ToString() ?? "";
                    var state = Convert.ToInt32(obj["productState"]);
                    if (((state >> 12) & 0xF) == 1) active.Add(name);
                }
                return (active.Count > 0, active.Count > 0 ? $"Active: {string.Join(", ", active)}" : "No active AV",
                    active.Count > 0 ? "" : "Install antivirus software");
            }
            catch
            {
                try
                {
                    using var sc = new ServiceController("WinDefend");
                    var ok = sc.Status == ServiceControllerStatus.Running;
                    return (ok, ok ? "Windows Defender running" : "Defender not running", ok ? "" : "Enable Windows Defender");
                }
                catch { return (false, "Unable to check AV", "Install antivirus"); }
            }
        });

        private SecurityCheck CheckFirewall() => RunCheck("firewall", "Windows Firewall", "Protection", 15, () =>
        {
            int enabled = 0;
            foreach (var profile in new[] { "DomainProfile", "StandardProfile", "PublicProfile" })
            {
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(
                        $@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{profile}");
                    if (key != null && Convert.ToInt32(key.GetValue("EnableFirewall", 0)) == 1) enabled++;
                }
                catch { }
            }
            return (enabled >= 2, $"Firewall enabled on {enabled}/3 profiles",
                enabled >= 2 ? "" : "Enable firewall for all profiles");
        });

        private SecurityCheck CheckUAC() => RunCheck("uac", "User Account Control", "Protection", 10, () =>
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System");
                var ok = key != null && Convert.ToInt32(key.GetValue("EnableLUA", 0)) == 1;
                return (ok, ok ? "UAC enabled" : "UAC DISABLED", ok ? "" : "Enable UAC");
            }
            catch { return (true, "Unable to check", ""); }
        });

        private SecurityCheck CheckBitLocker() => RunCheck("bitlocker", "Drive Encryption", "Data Protection", 10, () =>
        {
            try
            {
                using var searcher = new ManagementObjectSearcher("root\\CIMV2\\Security\\MicrosoftVolumeEncryption",
                    "SELECT DriveLetter, ProtectionStatus FROM Win32_EncryptableVolume");
                var sysDrive = Environment.GetFolderPath(Environment.SpecialFolder.Windows)[..2];
                foreach (ManagementObject obj in searcher.Get())
                {
                    if (obj["DriveLetter"]?.ToString()?.Equals(sysDrive, StringComparison.OrdinalIgnoreCase) == true
                        && Convert.ToInt32(obj["ProtectionStatus"]) == 1)
                        return (true, $"BitLocker active on {sysDrive}", "");
                }
                return (false, "System drive not encrypted", "Enable BitLocker");
            }
            catch { return (false, "BitLocker not available (may need Pro)", "Consider Windows Pro for BitLocker"); }
        });

        private SecurityCheck CheckWindowsVersion() => RunCheck("os_version", "Windows Version", "Updates", 10, () =>
        {
            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT Caption, BuildNumber FROM Win32_OperatingSystem");
                foreach (ManagementObject obj in searcher.Get())
                {
                    var caption = obj["Caption"]?.ToString() ?? "";
                    var build = int.TryParse(obj["BuildNumber"]?.ToString(), out var b) ? b : 0;
                    var ok = build >= 19041;
                    return (ok, $"{caption} (Build {build})", ok ? "" : "Update Windows");
                }
            }
            catch { }
            return (true, "Unable to check", "");
        });

        private SecurityCheck CheckRDP() => RunCheck("rdp", "Remote Desktop", "Network", 5, () =>
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Terminal Server");
                var disabled = key != null && Convert.ToInt32(key.GetValue("fDenyTSConnections", 1)) == 1;
                return (disabled, disabled ? "RDP disabled" : "RDP ENABLED", disabled ? "" : "Disable RDP if not needed");
            }
            catch { return (true, "Unable to check", ""); }
        });

        private SecurityCheck CheckGuestAccount() => RunCheck("guest", "Guest Account", "Access", 5, () =>
        {
            try
            {
                var psi = new ProcessStartInfo("net", "user Guest")
                { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                using var proc = Process.Start(psi);
                var output = proc?.StandardOutput.ReadToEnd() ?? "";
                proc?.WaitForExit(5000);
                bool active = false;
                foreach (var line in output.Split('\n'))
                    if (line.TrimStart().StartsWith("Account active", StringComparison.OrdinalIgnoreCase))
                    { active = line.Contains("Yes", StringComparison.OrdinalIgnoreCase); break; }
                return (!active, active ? "Guest account ENABLED" : "Guest account disabled",
                    active ? "Disable: net user Guest /active:no" : "");
            }
            catch { return (true, "Unable to check", ""); }
        });

        private SecurityCheck CheckAutoLogin() => RunCheck("autologin", "Auto-Login", "Access", 5, () =>
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon");
                if (key != null)
                {
                    var auto = key.GetValue("AutoAdminLogon")?.ToString() ?? "0";
                    var pass = key.GetValue("DefaultPassword")?.ToString();
                    var ok = auto != "1" || string.IsNullOrEmpty(pass);
                    return (ok, ok ? "Auto-login not configured" : "Auto-login ENABLED",
                        ok ? "" : "Disable auto-login");
                }
            }
            catch { }
            return (true, "Unable to check", "");
        });

        private SecurityCheck CheckSMBv1() => RunCheck("smbv1", "SMBv1 Protocol", "Network", 5, () =>
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters");
                if (key != null)
                {
                    var smb1 = key.GetValue("SMB1");
                    if (smb1 != null)
                    {
                        var disabled = Convert.ToInt32(smb1) == 0;
                        return (disabled, disabled ? "SMBv1 disabled" : "SMBv1 ENABLED (WannaCry vector)",
                            disabled ? "" : "Disable SMBv1");
                    }
                }
                return (true, "SMBv1 disabled (default)", "");
            }
            catch { return (true, "Unable to check", ""); }
        });

        private SecurityCheck CheckDefenderRealtime() => RunCheck("defender_rt", "Real-time Protection", "Protection", 5, () =>
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection");
                if (key != null)
                {
                    var disabled = Convert.ToInt32(key.GetValue("DisableRealtimeMonitoring", 0));
                    var ok = disabled == 0;
                    return (ok, ok ? "Real-time protection active" : "Real-time protection DISABLED",
                        ok ? "" : "Enable in Windows Security");
                }
                return (true, "Third-party AV may be active", "");
            }
            catch { return (true, "Unable to check", ""); }
        });

        private SecurityCheck CheckBackupStatus() => RunCheck("backup", "Backup Status", "Data Protection", 5, () =>
        {
            try
            {
                // Check Windows File History
                using var key = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\FileHistory");
                if (key != null)
                {
                    var protectedUntil = key.GetValue("ProtectedUpToTime");
                    if (protectedUntil != null)
                    {
                        var ft = Convert.ToInt64(protectedUntil);
                        var lastBackup = DateTime.FromFileTimeUtc(ft);
                        var daysSince = (DateTime.UtcNow - lastBackup).TotalDays;
                        if (daysSince <= 7)
                            return (true, $"File History: last backup {lastBackup:MMM d, yyyy h:mm tt} ({daysSince:F0} days ago)", "");
                        return (false, $"File History: last backup {lastBackup:MMM d, yyyy} ({daysSince:F0} days ago)", "Run a backup - last one was over a week ago");
                    }
                }

                // Check System Restore
                using var srKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore");
                if (srKey != null)
                {
                    var enabled = Convert.ToInt32(srKey.GetValue("RPSessionInterval", 0));
                    if (enabled > 0)
                        return (true, "System Restore enabled (no File History)", "Consider enabling File History backup");
                }

                return (false, "No backup solution configured", "Enable File History or install backup software");
            }
            catch { return (false, "Unable to check backup status", "Configure a backup solution"); }
        });

        private SecurityCheck CheckLastWindowsUpdate() => RunCheck("last_update", "Last Windows Update", "Updates", 5, () =>
        {
            try
            {
                // Check registry for last successful update time
                using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install");
                if (key != null)
                {
                    var lastSuccess = key.GetValue("LastSuccessTime")?.ToString();
                    if (!string.IsNullOrEmpty(lastSuccess) && DateTime.TryParse(lastSuccess, out var lastDate))
                    {
                        var daysSince = (DateTime.UtcNow - lastDate).TotalDays;
                        if (daysSince <= 30)
                            return (true, $"Last update installed: {lastDate:MMM d, yyyy} ({daysSince:F0} days ago)", "");
                        return (false, $"Last update: {lastDate:MMM d, yyyy} ({daysSince:F0} days ago)", "Check for updates - last install was over 30 days ago");
                    }
                }
                return (true, "Unable to determine last update date", "");
            }
            catch { return (true, "Unable to check", ""); }
        });

        private SecurityCheck CheckDiskSmartHealth() => RunCheck("disk_smart", "Disk SMART Health", "Data Protection", 5, () =>
        {
            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT Status, Caption FROM Win32_DiskDrive");
                var drives = new List<(string name, string status)>();
                foreach (ManagementObject obj in searcher.Get())
                {
                    var caption = obj["Caption"]?.ToString() ?? "Unknown";
                    var status = obj["Status"]?.ToString() ?? "Unknown";
                    drives.Add((caption, status));
                }
                if (drives.Count == 0)
                    return (true, "No disk drives detected", "");
                var unhealthy = drives.Where(d => d.status != "OK" && d.status != "Pred Fail").ToList();
                var predFail = drives.Where(d => d.status == "Pred Fail").ToList();
                if (predFail.Count > 0)
                    return (false, $"PREDICTED FAILURE: {predFail[0].name}", "Replace this drive immediately - failure predicted by SMART");
                if (unhealthy.Count > 0)
                    return (false, $"Drive issue: {unhealthy[0].name} ({unhealthy[0].status})", "Check drive health and consider replacement");
                return (true, $"{drives.Count} drive(s) healthy (Status: OK)", "");
            }
            catch { return (true, "Unable to query SMART status", ""); }
        });

        private SecurityCheck CheckSsdWearLevel() => RunCheck("ssd_wear", "SSD Wear Level", "Data Protection", 5, () =>
        {
            try
            {
                // Check via MSFT_PhysicalDisk (Win10+) for MediaType and Wear
                using var searcher = new ManagementObjectSearcher("root\\Microsoft\\Windows\\Storage",
                    "SELECT FriendlyName, MediaType, Wear FROM MSFT_PhysicalDisk");
                var ssds = new List<(string name, int? wear)>();
                foreach (ManagementObject obj in searcher.Get())
                {
                    var mediaType = Convert.ToInt32(obj["MediaType"]);
                    // MediaType: 3=HDD, 4=SSD, 5=SCM
                    if (mediaType == 4 || mediaType == 5)
                    {
                        var name = obj["FriendlyName"]?.ToString() ?? "SSD";
                        int? wear = null;
                        try { wear = Convert.ToInt32(obj["Wear"]); } catch { }
                        ssds.Add((name, wear));
                    }
                }
                if (ssds.Count == 0)
                    return (true, "No SSD detected (or HDD only)", "");
                foreach (var ssd in ssds)
                {
                    if (ssd.wear.HasValue)
                    {
                        var remaining = 100 - ssd.wear.Value;
                        if (remaining < 10)
                            return (false, $"{ssd.name}: {remaining}% life remaining (critical)", "SSD nearing end of life - plan replacement immediately");
                        if (remaining < 30)
                            return (false, $"{ssd.name}: {remaining}% life remaining (worn)", "SSD wear is elevated - consider planning replacement");
                        return (true, $"{ssd.name}: {remaining}% life remaining", "");
                    }
                }
                return (true, $"{ssds.Count} SSD(s) detected (wear data not available)", "");
            }
            catch { return (true, "Unable to query SSD wear level", ""); }
        });

        private SecurityCheck CheckBatteryHealth() => RunCheck("battery", "Battery Health", "Data Protection", 3, () =>
        {
            try
            {
                using var searcher = new ManagementObjectSearcher("root\\WMI",
                    "SELECT DesignedCapacity, FullChargedCapacity FROM BatteryFullChargedCapacity");
                foreach (ManagementObject obj in searcher.Get())
                {
                    var designed = Convert.ToInt32(obj["DesignedCapacity"]);
                    var fullCharge = Convert.ToInt32(obj["FullChargedCapacity"]);
                    if (designed > 0)
                    {
                        var healthPct = (int)((double)fullCharge / designed * 100);
                        if (healthPct < 40)
                            return (false, $"Battery health: {healthPct}% (critical - {fullCharge}mWh / {designed}mWh)", "Battery is severely degraded - recommend replacement");
                        if (healthPct < 60)
                            return (false, $"Battery health: {healthPct}% (degraded - {fullCharge}mWh / {designed}mWh)", "Battery is degraded - consider replacement");
                        return (true, $"Battery health: {healthPct}% ({fullCharge}mWh / {designed}mWh)", "");
                    }
                }
                // No battery = desktop, that's fine
                return (true, "No battery detected (desktop)", "");
            }
            catch { return (true, "No battery detected (desktop)", ""); }
        });

        private SecurityCheck CheckRamErrors() => RunCheck("ram_errors", "RAM Errors", "Data Protection", 5, () =>
        {
            try
            {
                // Check Windows Memory Diagnostic results from Event Log
                using var searcher = new ManagementObjectSearcher(
                    "SELECT Status FROM Win32_PhysicalMemory");
                var totalModules = 0;
                var badModules = 0;
                foreach (ManagementObject obj in searcher.Get())
                {
                    totalModules++;
                    var status = obj["Status"]?.ToString();
                    if (status != null && status != "OK" && status != "")
                        badModules++;
                }

                if (totalModules == 0)
                    return (true, "Unable to query RAM modules", "");

                // Also check for WHEA memory errors in event log
                try
                {
                    using var eventSearcher = new ManagementObjectSearcher(
                        "SELECT * FROM Win32_NTLogEvent WHERE Logfile='System' AND SourceName='Microsoft-Windows-WHEA-Logger' AND EventCode=19");
                    int wheaErrors = 0;
                    foreach (ManagementObject obj in eventSearcher.Get())
                        wheaErrors++;

                    if (wheaErrors > 0)
                        return (false, $"{totalModules} RAM module(s) - {wheaErrors} WHEA memory error(s) detected", "Run Windows Memory Diagnostic (mdsched.exe) and consider replacing faulty RAM");
                }
                catch { }

                if (badModules > 0)
                    return (false, $"{badModules}/{totalModules} RAM module(s) reporting errors", "Run Windows Memory Diagnostic and consider replacement");

                return (true, $"{totalModules} RAM module(s) healthy (Status: OK)", "");
            }
            catch { return (true, "Unable to query RAM health", ""); }
        });

        // === SOFTWARE & PATCHES ===

        private SecurityCheck CheckOutdatedSoftware() => RunCheck("outdated_sw", "Outdated Software", "Updates", 5, () =>
        {
            try
            {
                // Known software with version thresholds (name pattern -> min safe version)
                var softwareChecks = new Dictionary<string, (string pattern, System.Version minVersion, string latest)>
                {
                    {"Chrome", ("Google Chrome", new System.Version(120, 0), "120+")},
                    {"Firefox", ("Mozilla Firefox", new System.Version(120, 0), "120+")},
                    {"Edge", ("Microsoft Edge", new System.Version(120, 0), "120+")},
                    {"Adobe Reader", ("Adobe Acrobat Reader", new System.Version(24, 0), "2024+")},
                    {"7-Zip", ("7-Zip", new System.Version(23, 0), "23+")},
                    {"Zoom", ("Zoom", new System.Version(5, 17), "5.17+")},
                    {"VLC", ("VLC media player", new System.Version(3, 0, 20), "3.0.20+")},
                    {"Notepad++", ("Notepad++", new System.Version(8, 5), "8.5+")},
                    {"PuTTY", ("PuTTY", new System.Version(0, 80), "0.80+")},
                    {"WinSCP", ("WinSCP", new System.Version(6, 1), "6.1+")},
                    {"FileZilla", ("FileZilla", new System.Version(3, 66), "3.66+")},
                };

                var outdated = new List<string>();
                var scanned = 0;

                // Check via Uninstall registry keys (faster than Win32_Product)
                foreach (var regPath in new[] {
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                    @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
                })
                {
                    using var key = Registry.LocalMachine.OpenSubKey(regPath);
                    if (key == null) continue;
                    foreach (var subKeyName in key.GetSubKeyNames())
                    {
                        try
                        {
                            using var subKey = key.OpenSubKey(subKeyName);
                            var displayName = subKey?.GetValue("DisplayName")?.ToString() ?? "";
                            var displayVersion = subKey?.GetValue("DisplayVersion")?.ToString() ?? "";
                            if (string.IsNullOrEmpty(displayName) || string.IsNullOrEmpty(displayVersion)) continue;

                            scanned++;
                            foreach (var (_, (pattern, minVer, latest)) in softwareChecks)
                            {
                                if (displayName.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                                {
                                    if (System.Version.TryParse(displayVersion.Split('-')[0].Split(' ')[0], out var ver) && ver < minVer)
                                        outdated.Add($"{displayName} v{displayVersion} (need {latest})");
                                }
                            }
                        }
                        catch { }
                    }
                }

                if (outdated.Count > 0)
                    return (false, $"{outdated.Count} outdated: {string.Join("; ", outdated.Take(5))}", "Update these applications to patch known security vulnerabilities");
                return (true, $"All monitored software is up to date ({scanned} programs scanned)", "");
            }
            catch { return (true, "Unable to scan installed software versions", ""); }
        });

        private SecurityCheck CheckMissingCriticalUpdates() => RunCheck("critical_updates", "Critical Windows Updates", "Updates", 8, () =>
        {
            try
            {
                // Check via COM WUA (Windows Update Agent)
                var startInfo = new ProcessStartInfo("powershell", "-NoProfile -Command \"(New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search('IsInstalled=0 AND IsHidden=0 AND Type=\\'Software\\'').Updates.Count\"")
                {
                    RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true
                };
                using var proc = Process.Start(startInfo);
                var output = proc?.StandardOutput.ReadToEnd()?.Trim() ?? "";
                proc?.WaitForExit(30000); // 30 second timeout

                if (int.TryParse(output, out var count))
                {
                    if (count == 0)
                        return (true, "No pending Windows updates", "");
                    if (count <= 3)
                        return (true, $"{count} update(s) available", "Install pending updates when convenient");
                    return (false, $"{count} updates pending installation", "Install critical updates - unpatched systems are primary ransomware targets");
                }
                return (true, "Unable to query Windows Update status", "");
            }
            catch { return (true, "Unable to check for pending updates", ""); }
        });

        // === IDENTITY & ACCESS CHECKS ===

        private SecurityCheck CheckAdminAccountCount() => RunCheck("admin_count", "Admin Accounts", "Identity & Access", 5, () =>
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    "SELECT * FROM Win32_GroupUser WHERE GroupComponent=\"Win32_Group.Domain='" + Environment.MachineName + "',Name='Administrators'\"");
                var admins = new List<string>();
                foreach (ManagementObject obj in searcher.Get())
                {
                    var part = obj["PartComponent"]?.ToString() ?? "";
                    var nameMatch = System.Text.RegularExpressions.Regex.Match(part, "Name=\"(.+?)\"");
                    if (nameMatch.Success) admins.Add(nameMatch.Groups[1].Value);
                }
                if (admins.Count > 3)
                    return (false, $"{admins.Count} admin accounts: {string.Join(", ", admins.Take(5))}", "Too many admin accounts increases attack surface - remove unnecessary admin privileges");
                return (true, $"{admins.Count} admin account(s): {string.Join(", ", admins)}", "");
            }
            catch { return (true, "Unable to enumerate admin accounts", ""); }
        });

        private SecurityCheck CheckPasswordPolicy() => RunCheck("password_policy", "Password Policy", "Identity & Access", 5, () =>
        {
            try
            {
                // Check minimum password length policy
                using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters");
                var maxAge = key?.GetValue("MaximumPasswordAge");

                // Check if password complexity is enabled
                var startInfo = new ProcessStartInfo("net", "accounts")
                {
                    RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true
                };
                using var proc = Process.Start(startInfo);
                var output = proc?.StandardOutput.ReadToEnd() ?? "";
                proc?.WaitForExit();

                var minLength = 0;
                var maxDays = 0;
                foreach (var line in output.Split('\n'))
                {
                    if (line.Contains("Minimum password length"))
                    {
                        var parts = line.Split(':');
                        if (parts.Length > 1) int.TryParse(parts[1].Trim(), out minLength);
                    }
                    if (line.Contains("Maximum password age"))
                    {
                        var parts = line.Split(':');
                        if (parts.Length > 1) int.TryParse(parts[1].Trim(), out maxDays);
                    }
                }

                var issues = new List<string>();
                if (minLength < 8) issues.Add($"Min length {minLength} (should be 8+)");
                if (maxDays == 0 || maxDays > 90) issues.Add($"Max age {maxDays} days (should be 90 or less)");

                if (issues.Count > 0)
                    return (false, $"Weak policy: {string.Join(", ", issues)}", "Enforce minimum 8-character passwords with 90-day expiry");
                return (true, $"Min length: {minLength}, Max age: {maxDays} days", "");
            }
            catch { return (true, "Unable to check password policy", ""); }
        });

        private SecurityCheck CheckInactiveUsers() => RunCheck("inactive_users", "Inactive Users", "Identity & Access", 3, () =>
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    "SELECT Name, Disabled, Lockout FROM Win32_UserAccount WHERE LocalAccount=True");
                var total = 0;
                var disabled = 0;
                var enabled = new List<string>();
                foreach (ManagementObject obj in searcher.Get())
                {
                    total++;
                    var isDisabled = Convert.ToBoolean(obj["Disabled"]);
                    if (isDisabled) disabled++;
                    else enabled.Add(obj["Name"]?.ToString() ?? "");
                }
                if (enabled.Count > 5)
                    return (false, $"{enabled.Count} active user accounts (review needed)", "Review and disable unused accounts: " + string.Join(", ", enabled.Skip(3)));
                return (true, $"{enabled.Count} active, {disabled} disabled user accounts", "");
            }
            catch { return (true, "Unable to enumerate user accounts", ""); }
        });

        private SecurityCheck CheckPrivilegeEscalation() => RunCheck("priv_escalation", "Privilege Escalation Risk", "Identity & Access", 5, () =>
        {
            try
            {
                var risks = new List<string>();

                // Check if AlwaysInstallElevated is enabled (major risk)
                using (var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\Installer"))
                {
                    var val = key?.GetValue("AlwaysInstallElevated");
                    if (val != null && Convert.ToInt32(val) == 1)
                        risks.Add("AlwaysInstallElevated ENABLED (critical)");
                }

                // Check if WSUS is configured over HTTP (not HTTPS)
                using (var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"))
                {
                    var wsusUrl = key?.GetValue("WUServer")?.ToString();
                    if (wsusUrl != null && wsusUrl.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
                        risks.Add("WSUS over HTTP (MITM risk)");
                }

                // Check unquoted service paths
                using var svcSearcher = new ManagementObjectSearcher("SELECT Name, PathName FROM Win32_Service");
                var unquoted = 0;
                foreach (ManagementObject obj in svcSearcher.Get())
                {
                    var path = obj["PathName"]?.ToString() ?? "";
                    if (path.Contains(" ") && !path.StartsWith("\"") && !path.StartsWith("'"))
                        unquoted++;
                }
                if (unquoted > 3) risks.Add($"{unquoted} services with unquoted paths");

                if (risks.Count > 0)
                    return (false, string.Join("; ", risks), "Fix privilege escalation vectors - these are commonly exploited by malware");
                return (true, "No common privilege escalation risks detected", "");
            }
            catch { return (true, "Unable to check privilege escalation risks", ""); }
        });

        // === NETWORK CHECKS ===

        private SecurityCheck CheckRdpExposure() => RunCheck("rdp_exposure", "RDP Internet Exposure", "Network", 8, () =>
        {
            try
            {
                // Check if RDP is listening and if NLA (Network Level Auth) is required
                using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp");
                var rdpEnabled = false;
                using (var fDenyKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Terminal Server"))
                {
                    var fDeny = fDenyKey?.GetValue("fDenyTSConnections");
                    rdpEnabled = fDeny != null && Convert.ToInt32(fDeny) == 0;
                }

                if (!rdpEnabled) return (true, "RDP is disabled - not exposed", "");

                var nla = key?.GetValue("SecurityLayer");
                var nlaEnabled = nla != null && Convert.ToInt32(nla) >= 2;

                if (!nlaEnabled)
                    return (false, "RDP enabled WITHOUT Network Level Authentication", "Enable NLA for RDP - without it, attackers can exploit pre-authentication vulnerabilities");
                return (true, "RDP enabled with NLA (Network Level Authentication)", "");
            }
            catch { return (true, "Unable to check RDP exposure", ""); }
        });

        private SecurityCheck CheckOpenPorts() => RunCheck("open_ports", "Open Ports Scan", "Network", 5, () =>
        {
            try
            {
                var startInfo = new ProcessStartInfo("netstat", "-an")
                {
                    RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true
                };
                using var proc = Process.Start(startInfo);
                var output = proc?.StandardOutput.ReadToEnd() ?? "";
                proc?.WaitForExit();

                var riskyPorts = new Dictionary<int, string>
                {
                    {21, "FTP"}, {23, "Telnet"}, {445, "SMB"}, {1433, "SQL Server"},
                    {3306, "MySQL"}, {5432, "PostgreSQL"}, {5900, "VNC"}, {8080, "HTTP Proxy"},
                    {1900, "UPnP"}, {135, "RPC"}
                };

                var openRisky = new List<string>();
                foreach (var line in output.Split('\n'))
                {
                    if (line.Contains("LISTENING"))
                    {
                        var parts = line.Trim().Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length >= 2)
                        {
                            var addr = parts[1];
                            var portStr = addr.Contains(":") ? addr.Substring(addr.LastIndexOf(':') + 1) : "";
                            if (int.TryParse(portStr, out var port) && riskyPorts.ContainsKey(port))
                            {
                                if (addr.StartsWith("0.0.0.0") || addr.StartsWith("[::]"))
                                    openRisky.Add($"{port} ({riskyPorts[port]})");
                            }
                        }
                    }
                }

                if (openRisky.Count > 3)
                    return (false, $"{openRisky.Count} risky ports open: {string.Join(", ", openRisky.Take(5))}", "Review and close unnecessary services - these ports are commonly targeted");
                if (openRisky.Count > 0)
                    return (true, $"{openRisky.Count} notable port(s): {string.Join(", ", openRisky)}", "");
                return (true, "No high-risk ports open to all interfaces", "");
            }
            catch { return (true, "Unable to scan open ports", ""); }
        });

        private SecurityCheck CheckDnsSecurity() => RunCheck("dns_security", "DNS Security", "Network", 3, () =>
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    "SELECT DNSServerSearchOrder FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=True");
                var dnsServers = new List<string>();
                foreach (ManagementObject obj in searcher.Get())
                {
                    var dns = obj["DNSServerSearchOrder"] as string[];
                    if (dns != null) dnsServers.AddRange(dns);
                }

                var secureDns = new HashSet<string> {
                    "1.1.1.2", "1.1.1.3",  // Cloudflare malware blocking
                    "9.9.9.9", "149.112.112.112",  // Quad9
                    "8.8.8.8", "8.8.4.4",  // Google
                    "208.67.222.222", "208.67.220.220"  // OpenDNS
                };

                var usingSecure = dnsServers.Any(d => secureDns.Contains(d));
                if (dnsServers.Count == 0)
                    return (true, "DNS configured via DHCP", "");
                if (usingSecure)
                    return (true, $"Using secure DNS: {string.Join(", ", dnsServers.Take(2))}", "");
                return (false, $"DNS: {string.Join(", ", dnsServers.Take(2))} (not filtered)", "Consider using security-focused DNS like Quad9 (9.9.9.9) or Cloudflare (1.1.1.2) for malware blocking");
            }
            catch { return (true, "Unable to check DNS configuration", ""); }
        });

        private SecurityCheck CheckWifiSecurity() => RunCheck("wifi_security", "WiFi Security", "Network", 3, () =>
        {
            try
            {
                var startInfo = new ProcessStartInfo("netsh", "wlan show interfaces")
                {
                    RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true
                };
                using var proc = Process.Start(startInfo);
                var output = proc?.StandardOutput.ReadToEnd() ?? "";
                proc?.WaitForExit();

                if (string.IsNullOrWhiteSpace(output) || output.Contains("no wireless"))
                    return (true, "No WiFi connection active (wired or no adapter)", "");

                var authLine = output.Split('\n').FirstOrDefault(l => l.Trim().StartsWith("Authentication"));
                var auth = authLine?.Split(':').LastOrDefault()?.Trim() ?? "Unknown";

                if (auth.Contains("WPA3", StringComparison.OrdinalIgnoreCase))
                    return (true, $"WiFi security: {auth} (strongest)", "");
                if (auth.Contains("WPA2", StringComparison.OrdinalIgnoreCase))
                    return (true, $"WiFi security: {auth} (good)", "");
                if (auth.Contains("WPA", StringComparison.OrdinalIgnoreCase))
                    return (false, $"WiFi security: {auth} (outdated)", "Upgrade to WPA2 or WPA3 - WPA is vulnerable to attacks");
                if (auth.Contains("Open", StringComparison.OrdinalIgnoreCase) || auth.Contains("WEP", StringComparison.OrdinalIgnoreCase))
                    return (false, $"WiFi security: {auth} (INSECURE)", "Immediately switch to WPA2/WPA3 - this network is not secure");
                return (true, $"WiFi security: {auth}", "");
            }
            catch { return (true, "Unable to check WiFi security", ""); }
        });

        private SecurityCheck CheckVpnStatus() => RunCheck("vpn_status", "VPN Status", "Network", 2, () =>
        {
            try
            {
                // Check for VPN adapters
                using var searcher = new ManagementObjectSearcher(
                    "SELECT Name, Description FROM Win32_NetworkAdapter WHERE NetEnabled=True");
                var vpnAdapters = new List<string>();
                foreach (ManagementObject obj in searcher.Get())
                {
                    var name = (obj["Name"]?.ToString() ?? "") + " " + (obj["Description"]?.ToString() ?? "");
                    if (name.Contains("VPN", StringComparison.OrdinalIgnoreCase) ||
                        name.Contains("WireGuard", StringComparison.OrdinalIgnoreCase) ||
                        name.Contains("OpenVPN", StringComparison.OrdinalIgnoreCase) ||
                        name.Contains("TAP-", StringComparison.OrdinalIgnoreCase) ||
                        name.Contains("Tunnel", StringComparison.OrdinalIgnoreCase))
                        vpnAdapters.Add(obj["Name"]?.ToString() ?? "VPN");
                }

                if (vpnAdapters.Count > 0)
                    return (true, $"VPN active: {string.Join(", ", vpnAdapters)}", "");
                return (true, "No VPN connection detected", "Consider using a VPN for remote workers");
            }
            catch { return (true, "Unable to check VPN status", ""); }
        });

        // === RANSOMWARE PROTECTION CHECKS ===

        private SecurityCheck CheckShadowCopies() => RunCheck("shadow_copies", "Shadow Copies (VSS)", "Ransomware Protection", 8, () =>
        {
            try
            {
                var startInfo = new ProcessStartInfo("vssadmin", "list shadows")
                {
                    RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true
                };
                using var proc = Process.Start(startInfo);
                var output = proc?.StandardOutput.ReadToEnd() ?? "";
                proc?.WaitForExit();

                if (output.Contains("No items found") || !output.Contains("Shadow Copy"))
                    return (false, "No shadow copies found - data recovery NOT possible", "Enable System Protection and create regular restore points for ransomware recovery");

                var count = output.Split('\n').Count(l => l.Contains("Shadow Copy ID"));
                return (true, $"{count} shadow copy/copies available for recovery", "");
            }
            catch { return (false, "Unable to query shadow copies", "Ensure Volume Shadow Copy service is running"); }
        });

        private SecurityCheck CheckBackupFrequency() => RunCheck("backup_freq", "Backup Frequency", "Ransomware Protection", 5, () =>
        {
            try
            {
                // Check File History
                using var key = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\FileHistory");
                var fhEnabled = key?.GetValue("ProtectedUpToTime");
                if (fhEnabled != null)
                {
                    var lastBackup = DateTime.FromFileTimeUtc(Convert.ToInt64(fhEnabled));
                    var hoursSince = (DateTime.UtcNow - lastBackup).TotalHours;
                    if (hoursSince <= 24)
                        return (true, $"File History: last backup {hoursSince:F0} hours ago", "");
                    if (hoursSince <= 72)
                        return (true, $"File History: last backup {hoursSince / 24:F0} days ago", "Consider increasing backup frequency");
                    return (false, $"File History: last backup {hoursSince / 24:F0} days ago (stale)", "Backup is outdated - check File History for errors");
                }

                // Check Windows Backup
                using var wbKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsBackup\Status");
                if (wbKey != null)
                {
                    var lastSuccess = wbKey.GetValue("LastSuccessfulBackupTargetVolume");
                    if (lastSuccess != null)
                        return (true, "Windows Backup configured", "");
                }

                return (false, "No automated backup schedule detected", "Set up File History or a third-party backup solution with daily schedule");
            }
            catch { return (false, "Unable to check backup frequency", "Configure automated backups"); }
        });

        private SecurityCheck CheckFolderProtection() => RunCheck("folder_protection", "Protected Folders", "Ransomware Protection", 5, () =>
        {
            try
            {
                // Check if Controlled Folder Access has protected folders configured
                using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access\ProtectedFolders");
                if (key != null)
                {
                    var folders = key.GetValueNames();
                    if (folders.Length > 0)
                        return (true, $"{folders.Length} protected folder(s) configured", "");
                }

                // Also check if Documents/Desktop are on OneDrive (some protection)
                var oneDrive = Environment.GetEnvironmentVariable("OneDrive");
                if (!string.IsNullOrEmpty(oneDrive) && Directory.Exists(oneDrive))
                    return (true, "OneDrive sync detected (provides file versioning)", "");

                return (false, "No folder protection configured", "Enable Controlled Folder Access or sync important folders to OneDrive for versioning");
            }
            catch { return (true, "Unable to check folder protection", ""); }
        });

        // === EDR & ADVANCED CHECKS ===

        private SecurityCheck CheckExploitProtection() => RunCheck("exploit_guard", "Exploit Protection", "EDR & Advanced", 5, () =>
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Exploit Protection\System");
                if (key != null)
                {
                    // Check DEP, ASLR, SEHOP
                    var dep = key.GetValue("DEP");
                    var aslr = key.GetValue("ForceRelocateImages");
                    var cfgEnabled = dep != null || aslr != null;
                    return (cfgEnabled, cfgEnabled ? "Exploit Protection configured (DEP/ASLR)" : "Exploit Protection not configured", cfgEnabled ? "" : "Enable Windows Exploit Guard for DEP, ASLR, and SEHOP protections");
                }
                // DEP is usually on by default
                return (true, "Default exploit protection active (DEP enabled)", "");
            }
            catch { return (true, "Default exploit protection active", ""); }
        });

        private SecurityCheck CheckControlledFolderAccess() => RunCheck("cfa", "Controlled Folder Access", "Ransomware Protection", 10, () =>
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access");
                var enabled = key?.GetValue("EnableControlledFolderAccess");
                if (enabled != null && Convert.ToInt32(enabled) == 1)
                    return (true, "Controlled Folder Access ENABLED - ransomware protection active", "");
                return (false, "Controlled Folder Access DISABLED", "Enable Controlled Folder Access in Windows Security > Ransomware protection - this blocks unauthorized apps from modifying your files");
            }
            catch { return (false, "Unable to check Controlled Folder Access", "Enable Controlled Folder Access for ransomware protection"); }
        });

        private SecurityCheck CheckTamperProtection() => RunCheck("tamper_protect", "Tamper Protection", "EDR & Advanced", 5, () =>
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows Defender\Features");
                var tp = key?.GetValue("TamperProtection");
                if (tp != null && Convert.ToInt32(tp) == 5)
                    return (true, "Tamper Protection enabled - malware cannot disable Defender", "");
                return (false, "Tamper Protection DISABLED", "Enable Tamper Protection in Windows Security to prevent malware from disabling your antivirus");
            }
            catch { return (true, "Unable to check Tamper Protection status", ""); }
        });

        private SecurityCheck CheckCredentialGuard() => RunCheck("cred_guard", "Credential Guard", "Identity & Access", 5, () =>
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\DeviceGuard");
                var enabled = key?.GetValue("EnableVirtualizationBasedSecurity");
                if (enabled != null && Convert.ToInt32(enabled) == 1)
                    return (true, "Credential Guard / VBS enabled - credentials protected", "");

                // Check if running via WMI
                using var searcher = new ManagementObjectSearcher("root\\Microsoft\\Windows\\DeviceGuard",
                    "SELECT * FROM Win32_DeviceGuard");
                foreach (ManagementObject obj in searcher.Get())
                {
                    var vbsStatus = obj["VirtualizationBasedSecurityStatus"];
                    if (vbsStatus != null && Convert.ToInt32(vbsStatus) == 2)
                        return (true, "Virtualization-Based Security running", "");
                }

                return (false, "Credential Guard / VBS not enabled", "Enable Virtualization-Based Security for credential isolation (requires compatible hardware)");
            }
            catch { return (true, "Unable to check Credential Guard (may require Pro/Enterprise)", ""); }
        });

        private SecurityCheck CheckLsassProtection() => RunCheck("lsass_protect", "LSASS Protection", "Identity & Access", 5, () =>
        {
            try
            {
                // Check if LSASS runs as Protected Process Light (PPL)
                using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Lsa");
                var runAsPPL = key?.GetValue("RunAsPPL");
                if (runAsPPL != null && Convert.ToInt32(runAsPPL) == 1)
                    return (true, "LSASS Protected Process Light (PPL) enabled", "");
                return (false, "LSASS protection not enabled", "Enable LSASS PPL to prevent credential dumping attacks (mimikatz protection)");
            }
            catch { return (true, "Unable to check LSASS protection", ""); }
        });

        private SecurityCheck CheckEdrInstalled() => RunCheck("edr", "EDR / Advanced Protection", "EDR & Advanced", 5, () =>
        {
            try
            {
                var edrProducts = new[] {
                    "CrowdStrike", "SentinelOne", "Carbon Black", "CylancePROTECT",
                    "Sophos Intercept", "Malwarebytes Endpoint", "ESET Endpoint",
                    "Trend Micro", "Bitdefender GravityZone", "Huntress",
                    "Webroot", "Datto EDR", "Acronis"
                };

                using var searcher = new ManagementObjectSearcher(
                    "SELECT DisplayName FROM Win32_Product");
                var found = new List<string>();
                try
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        var name = obj["DisplayName"]?.ToString() ?? "";
                        foreach (var edr in edrProducts)
                            if (name.Contains(edr, StringComparison.OrdinalIgnoreCase))
                                found.Add(name);
                    }
                }
                catch { }

                // Also check running processes for EDR
                var edrProcesses = new Dictionary<string, string> {
                    {"CSFalconService", "CrowdStrike"}, {"SentinelAgent", "SentinelOne"},
                    {"CbDefense", "Carbon Black"}, {"MBAMService", "Malwarebytes"},
                    {"HuntressAgent", "Huntress"}, {"SophosUI", "Sophos"},
                    {"bdagent", "Bitdefender"}
                };
                foreach (var proc in Process.GetProcesses())
                {
                    try
                    {
                        if (edrProcesses.TryGetValue(proc.ProcessName, out var edrName))
                            if (!found.Contains(edrName)) found.Add(edrName);
                    }
                    catch { }
                    finally { try { proc.Dispose(); } catch { } }
                }

                if (found.Count > 0)
                    return (true, $"EDR detected: {string.Join(", ", found.Distinct())}", "");
                return (false, "No EDR / advanced threat protection detected", "Consider deploying an EDR solution for advanced threat detection beyond basic antivirus");
            }
            catch { return (true, "Unable to check for EDR products", ""); }
        });

        private SecurityCheck CheckPowerShellLogging() => RunCheck("ps_logging", "PowerShell Logging", "EDR & Advanced", 5, () =>
        {
            try
            {
                var issues = new List<string>();

                // Script Block Logging
                using (var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"))
                {
                    var enabled = key?.GetValue("EnableScriptBlockLogging");
                    if (enabled == null || Convert.ToInt32(enabled) != 1)
                        issues.Add("Script Block Logging disabled");
                }

                // Module Logging
                using (var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"))
                {
                    var enabled = key?.GetValue("EnableModuleLogging");
                    if (enabled == null || Convert.ToInt32(enabled) != 1)
                        issues.Add("Module Logging disabled");
                }

                // Transcription
                using (var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"))
                {
                    var enabled = key?.GetValue("EnableTranscripting");
                    if (enabled == null || Convert.ToInt32(enabled) != 1)
                        issues.Add("Transcription disabled");
                }

                if (issues.Count == 3)
                    return (false, "No PowerShell logging enabled", "Enable PowerShell Script Block Logging and Module Logging - attackers heavily use PowerShell");
                if (issues.Count > 0)
                    return (false, $"Partial logging: {string.Join(", ", issues)}", "Enable all PowerShell logging for complete visibility");
                return (true, "PowerShell logging fully enabled (script block + module + transcription)", "");
            }
            catch { return (true, "Unable to check PowerShell logging", ""); }
        });

        private SecurityCheck CheckScriptExecutionPolicy() => RunCheck("ps_exec_policy", "Script Execution Policy", "EDR & Advanced", 3, () =>
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell");
                var policy = key?.GetValue("ExecutionPolicy")?.ToString() ?? "Restricted";

                if (policy.Equals("Unrestricted", StringComparison.OrdinalIgnoreCase) ||
                    policy.Equals("Bypass", StringComparison.OrdinalIgnoreCase))
                    return (false, $"PowerShell execution policy: {policy} (dangerous)", "Set execution policy to RemoteSigned or AllSigned to prevent running untrusted scripts");
                return (true, $"PowerShell execution policy: {policy}", "");
            }
            catch { return (true, "Unable to check execution policy", ""); }
        });

        private SecurityCheck CheckSecureBoot() => RunCheck("secure_boot", "Secure Boot & TPM", "EDR & Advanced", 5, () =>
        {
            try
            {
                var secureBoot = false;
                var tpmPresent = false;

                // Check Secure Boot
                using (var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\SecureBoot\State"))
                {
                    var val = key?.GetValue("UEFISecureBootEnabled");
                    secureBoot = val != null && Convert.ToInt32(val) == 1;
                }

                // Check TPM
                try
                {
                    using var searcher = new ManagementObjectSearcher("root\\CIMv2\\Security\\MicrosoftTpm",
                        "SELECT * FROM Win32_Tpm");
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        tpmPresent = true;
                        break;
                    }
                }
                catch { }

                if (secureBoot && tpmPresent)
                    return (true, "Secure Boot enabled + TPM present", "");
                var issues = new List<string>();
                if (!secureBoot) issues.Add("Secure Boot disabled");
                if (!tpmPresent) issues.Add("TPM not detected");
                return (false, string.Join(", ", issues), "Enable Secure Boot in BIOS and ensure TPM is active for boot integrity");
            }
            catch { return (true, "Unable to check Secure Boot status", ""); }
        });

        private SecurityCheck CheckAttackSurfaceReduction() => RunCheck("asr_rules", "Attack Surface Reduction", "EDR & Advanced", 5, () =>
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules");
                if (key != null)
                {
                    var rules = key.GetValueNames();
                    var enabledCount = 0;
                    foreach (var rule in rules)
                    {
                        var val = key.GetValue(rule);
                        if (val != null && Convert.ToInt32(val) == 1) enabledCount++;
                    }
                    if (enabledCount > 0)
                        return (true, $"{enabledCount} ASR rules enabled", "");
                }
                return (false, "No Attack Surface Reduction rules configured", "Enable ASR rules to block Office macro abuse, credential stealing, and process injection attacks");
            }
            catch { return (false, "Unable to check ASR rules", "Configure ASR rules for advanced threat prevention"); }
        });

        private SecurityCheck CheckSuspiciousScheduledTasks() => RunCheck("sched_tasks", "Suspicious Scheduled Tasks", "EDR & Advanced", 3, () =>
        {
            try
            {
                var startInfo = new ProcessStartInfo("schtasks", "/query /fo CSV /nh")
                {
                    RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true
                };
                using var proc = Process.Start(startInfo);
                var output = proc?.StandardOutput.ReadToEnd() ?? "";
                proc?.WaitForExit();

                var suspiciousKeywords = new[] { "powershell -e", "cmd /c", "certutil", "bitsadmin", "mshta", "wscript", "cscript" };
                var suspicious = new List<string>();

                foreach (var line in output.Split('\n'))
                {
                    var lower = line.ToLowerInvariant();
                    foreach (var keyword in suspiciousKeywords)
                    {
                        if (lower.Contains(keyword))
                        {
                            var taskName = line.Split(',').FirstOrDefault()?.Trim('"') ?? "";
                            if (!string.IsNullOrEmpty(taskName) && !taskName.StartsWith("\\Microsoft"))
                                suspicious.Add(taskName);
                            break;
                        }
                    }
                }

                suspicious = suspicious.Distinct().Take(5).ToList();
                if (suspicious.Count > 0)
                    return (false, $"{suspicious.Count} suspicious task(s): {string.Join(", ", suspicious)}", "Review these scheduled tasks - they use techniques common in malware persistence");
                return (true, "No suspicious scheduled tasks detected", "");
            }
            catch { return (true, "Unable to scan scheduled tasks", ""); }
        });

        private SecurityCheck CheckEndOfLifeSoftware() => RunCheck("eol_software", "End-of-Life Software", "Updates", 5, () =>
        {
            try
            {
                var eolPatterns = new Dictionary<string, string> {
                    {"Windows 7", "OS"}, {"Windows 8", "OS"}, {"Windows XP", "OS"},
                    {"Adobe Flash", "Plugin"}, {"Java 6", "Runtime"}, {"Java 7", "Runtime"},
                    {"Java 8", "Runtime"}, {"Internet Explorer", "Browser"},
                    {"Microsoft Office 2010", "Office"}, {"Microsoft Office 2013", "Office"},
                    {"Python 2", "Runtime"}, {".NET Framework 3.5", "Runtime"}
                };

                // Check OS
                var osVersion = Environment.OSVersion.Version;
                if (osVersion.Build < 19041) // Before Windows 10 2004
                    return (false, "Operating system may be end-of-life or unsupported", "Upgrade to a supported version of Windows");

                // Check installed software
                var found = new List<string>();
                using var searcher = new ManagementObjectSearcher(
                    "SELECT Name, Version FROM Win32_Product");
                try
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        var name = obj["Name"]?.ToString() ?? "";
                        foreach (var (pattern, category) in eolPatterns)
                        {
                            if (name.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                            {
                                found.Add($"{name} ({category})");
                                break;
                            }
                        }
                    }
                }
                catch { }

                if (found.Count > 0)
                    return (false, $"{found.Count} EOL software: {string.Join(", ", found.Take(3))}", "Remove or update end-of-life software - no security patches available");
                return (true, "No end-of-life software detected", "");
            }
            catch { return (true, "Unable to check for EOL software", ""); }
        });

        private static SecurityCheck RunCheck(string id, string name, string category, int weight,
            Func<(bool passed, string detail, string recommendation)> check)
        {
            var result = new SecurityCheck { Id = id, Name = name, Category = category, Weight = weight };
            try
            {
                var (passed, detail, rec) = check();
                result.Passed = passed;
                result.Detail = detail;
                result.Recommendation = rec;
            }
            catch (Exception ex)
            {
                result.Passed = true;
                result.Detail = $"Check error: {ex.Message}";
            }
            return result;
        }
    }
}
