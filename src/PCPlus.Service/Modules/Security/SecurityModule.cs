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
                CheckDefenderRealtime()
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
                var ok = sc.Status == ServiceControllerStatus.Running || sc.StartType != ServiceControllerStartMode.Disabled;
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
