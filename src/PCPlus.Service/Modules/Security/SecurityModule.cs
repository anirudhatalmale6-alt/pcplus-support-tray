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

                default:
                    return Task.FromResult(ModuleResponse.Fail($"Unknown: {command.Action}"));
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
                CheckWindowsUpdate(),
                CheckAntivirus(),
                CheckFirewall(),
                CheckUAC(),
                CheckBitLocker(),
                CheckWindowsVersion(),
                CheckRDP(),
                CheckGuestAccount(),
                CheckAutoLogin(),
                CheckSMBv1(),
                CheckDefenderRealtime(),
                CheckBackupStatus(),
                CheckLastWindowsUpdate(),
                CheckDiskSmartHealth(),
                CheckSsdWearLevel(),
                CheckBatteryHealth(),
                CheckRamErrors()
            };

            var score = checks.Where(c => c.Passed).Sum(c => c.Weight);
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
