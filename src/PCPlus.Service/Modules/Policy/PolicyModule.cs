using System.Diagnostics;
using System.Management;
using System.Text.Json;
using Microsoft.Win32;
using PCPlus.Core.Interfaces;
using PCPlus.Core.Models;

namespace PCPlus.Service.Modules.Policy
{
    /// <summary>
    /// Policy enforcement module. Enforces security rules per client/device.
    /// USB blocking, PowerShell restriction, BitLocker enforcement,
    /// RDP blocking, screensaver lock, password policy, auto-lock.
    /// Custom rules from central dashboard.
    /// Premium tier.
    /// </summary>
    public class PolicyModule : IModule
    {
        public string Id => "policy";
        public string Name => "Policy Engine";
        public string Version => "4.1.0";
        public LicenseTier RequiredTier => LicenseTier.Premium;
        public bool IsRunning { get; private set; }

        private IModuleContext _context = null!;
        private Timer? _enforcementTimer;
        private readonly List<PolicyRule> _rules = new();
        private readonly List<PolicyViolation> _violations = new();
        private DateTime _lastDashboardSync = DateTime.MinValue;

        public Task InitializeAsync(IModuleContext context)
        {
            _context = context;
            LoadPolicies();
            return Task.CompletedTask;
        }

        public Task StartAsync(CancellationToken cancellationToken)
        {
            IsRunning = true;
            _enforcementTimer = new Timer(_ => EnforcePolicies(), null,
                TimeSpan.Zero, TimeSpan.FromSeconds(60));
            return Task.CompletedTask;
        }

        public Task StopAsync()
        {
            _enforcementTimer?.Dispose();
            IsRunning = false;
            return Task.CompletedTask;
        }

        public Task<ModuleResponse> HandleCommandAsync(ModuleCommand command)
        {
            switch (command.Action)
            {
                case "GetPolicies":
                    return Task.FromResult(ModuleResponse.Ok("", new Dictionary<string, object>
                    {
                        ["rules"] = _rules,
                        ["violations"] = _violations.TakeLast(50).ToList(),
                        ["stats"] = new Dictionary<string, object>
                        {
                            ["totalRules"] = _rules.Count,
                            ["activeRules"] = _rules.Count(r => r.Enabled),
                            ["totalViolations"] = _violations.Count,
                            ["lastEnforcement"] = DateTime.UtcNow
                        }
                    }));

                case "AddPolicy":
                    return HandleAddPolicy(command);

                case "RemovePolicy":
                    var removeId = command.Parameters.GetValueOrDefault("ruleId", "");
                    _rules.RemoveAll(r => r.Id == removeId);
                    SavePolicies();
                    return Task.FromResult(ModuleResponse.Ok($"Rule {removeId} removed"));

                case "TogglePolicy":
                    var toggleId = command.Parameters.GetValueOrDefault("ruleId", "");
                    var rule = _rules.FirstOrDefault(r => r.Id == toggleId);
                    if (rule != null)
                    {
                        rule.Enabled = !rule.Enabled;
                        SavePolicies();
                        return Task.FromResult(ModuleResponse.Ok($"Rule {toggleId} {(rule.Enabled ? "enabled" : "disabled")}"));
                    }
                    return Task.FromResult(ModuleResponse.Fail("Rule not found"));

                case "SyncFromDashboard":
                    return HandleDashboardSync(command);

                case "event":
                    return Task.FromResult(ModuleResponse.Ok());

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
            StatusText = $"{_rules.Count(r => r.Enabled)} rules active, {_violations.Count} violations",
            LastActivity = DateTime.UtcNow,
            Metrics = new()
            {
                ["activeRules"] = _rules.Count(r => r.Enabled),
                ["totalRules"] = _rules.Count,
                ["violations24h"] = _violations.Count(v => v.Timestamp > DateTime.UtcNow.AddHours(-24)),
                ["violationsTotal"] = _violations.Count,
                ["categories"] = string.Join(",", _rules.Where(r => r.Enabled).Select(r => r.Category).Distinct()),
                ["lastSync"] = _lastDashboardSync
            }
        };

        // === Policy Loading ===

        private void LoadPolicies()
        {
            var cfg = _context.Config;

            // Built-in policies from config
            AddBuiltInRule("block_usb", "Block USB Storage", "usb", PolicyAction.Block, cfg.BlockUSB);
            AddBuiltInRule("block_ps", "Block PowerShell", "powershell", PolicyAction.Block, cfg.BlockPowerShell);
            AddBuiltInRule("enforce_bitlocker", "Enforce BitLocker", "bitlocker", PolicyAction.Alert, cfg.EnforceBitLocker);

            // Default security policies (always on)
            AddBuiltInRule("check_rdp", "Monitor RDP Access", "rdp", PolicyAction.Audit, true);
            AddBuiltInRule("check_autorun", "Block AutoRun", "autorun", PolicyAction.Block, true);
            AddBuiltInRule("check_guest", "Disable Guest Account", "accounts", PolicyAction.AutoFix, true);
            AddBuiltInRule("check_screenlock", "Enforce Screen Lock", "screenlock", PolicyAction.Alert, true);

            // Load custom rules from file
            LoadCustomRules();
        }

        private void AddBuiltInRule(string id, string name, string category, PolicyAction action, bool enabled)
        {
            if (_rules.Any(r => r.Id == id)) return;
            _rules.Add(new PolicyRule
            {
                Id = id, Name = name, Category = category,
                Action = action, Enabled = enabled
            });
        }

        private void LoadCustomRules()
        {
            try
            {
                var rulesFile = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "PCPlusEndpoint", "policies.json");
                if (File.Exists(rulesFile))
                {
                    var json = File.ReadAllText(rulesFile);
                    var customRules = JsonSerializer.Deserialize<List<PolicyRule>>(json,
                        new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                    if (customRules != null)
                    {
                        foreach (var rule in customRules)
                        {
                            if (!_rules.Any(r => r.Id == rule.Id))
                                _rules.Add(rule);
                        }
                    }
                }
            }
            catch { }
        }

        private void SavePolicies()
        {
            try
            {
                var customRules = _rules.Where(r => !r.Id.StartsWith("block_") && !r.Id.StartsWith("enforce_") && !r.Id.StartsWith("check_")).ToList();
                var rulesFile = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "PCPlusEndpoint", "policies.json");
                var json = JsonSerializer.Serialize(customRules, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(rulesFile, json);
            }
            catch { }
        }

        // === Policy Enforcement ===

        private void EnforcePolicies()
        {
            foreach (var rule in _rules.Where(r => r.Enabled))
            {
                try
                {
                    switch (rule.Category)
                    {
                        case "usb": EnforceUsbPolicy(rule); break;
                        case "powershell": EnforcePowerShellPolicy(rule); break;
                        case "bitlocker": EnforceBitLockerPolicy(rule); break;
                        case "rdp": EnforceRdpPolicy(rule); break;
                        case "autorun": EnforceAutoRunPolicy(rule); break;
                        case "accounts": EnforceAccountPolicy(rule); break;
                        case "screenlock": EnforceScreenLockPolicy(rule); break;
                    }
                }
                catch { }
            }
        }

        private void EnforceUsbPolicy(PolicyRule rule)
        {
            if (rule.Action != PolicyAction.Block) return;
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Services\USBSTOR", true);
                if (key != null)
                {
                    var current = Convert.ToInt32(key.GetValue("Start", 3));
                    if (current != 4)
                    {
                        key.SetValue("Start", 4, RegistryValueKind.DWord);
                        RecordViolation(rule, "USB storage was enabled - blocked by policy");
                    }
                }
            }
            catch { }
        }

        private void EnforcePowerShellPolicy(PolicyRule rule)
        {
            if (rule.Action != PolicyAction.Block) return;
            try
            {
                foreach (var name in new[] { "powershell", "pwsh" })
                {
                    foreach (var proc in Process.GetProcessesByName(name))
                    {
                        proc.Kill();
                        RecordViolation(rule, $"{name} process killed (PID {proc.Id})");
                        proc.Dispose();
                    }
                }
            }
            catch { }
        }

        private void EnforceBitLockerPolicy(PolicyRule rule)
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    "root\\CIMV2\\Security\\MicrosoftVolumeEncryption",
                    "SELECT DriveLetter, ProtectionStatus FROM Win32_EncryptableVolume");
                var sysDrive = Environment.GetFolderPath(Environment.SpecialFolder.Windows)[..2];

                foreach (ManagementObject obj in searcher.Get())
                {
                    if (obj["DriveLetter"]?.ToString()?.Equals(sysDrive, StringComparison.OrdinalIgnoreCase) == true)
                    {
                        var status = Convert.ToInt32(obj["ProtectionStatus"]);
                        if (status != 1)
                        {
                            RecordViolation(rule, $"BitLocker not active on {sysDrive}");
                        }
                    }
                }
            }
            catch { }
        }

        private void EnforceRdpPolicy(PolicyRule rule)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Control\Terminal Server");
                if (key != null)
                {
                    var rdpEnabled = Convert.ToInt32(key.GetValue("fDenyTSConnections", 1)) == 0;
                    if (rdpEnabled)
                    {
                        if (rule.Action == PolicyAction.Block)
                        {
                            using var writeKey = Registry.LocalMachine.OpenSubKey(
                                @"SYSTEM\CurrentControlSet\Control\Terminal Server", true);
                            writeKey?.SetValue("fDenyTSConnections", 1, RegistryValueKind.DWord);
                            RecordViolation(rule, "RDP was enabled - disabled by policy");
                        }
                        else
                        {
                            RecordViolation(rule, "RDP is enabled on this machine");
                        }
                    }
                }
            }
            catch { }
        }

        private void EnforceAutoRunPolicy(PolicyRule rule)
        {
            try
            {
                // Disable AutoRun for all drive types
                using var key = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", true);
                if (key != null)
                {
                    var current = Convert.ToInt32(key.GetValue("NoDriveTypeAutoRun", 0));
                    if (current != 255) // 0xFF = disable all
                    {
                        key.SetValue("NoDriveTypeAutoRun", 255, RegistryValueKind.DWord);
                        RecordViolation(rule, "AutoRun was enabled - disabled by policy");
                    }
                }
                else
                {
                    using var createKey = Registry.LocalMachine.CreateSubKey(
                        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer");
                    createKey?.SetValue("NoDriveTypeAutoRun", 255, RegistryValueKind.DWord);
                }
            }
            catch { }
        }

        private void EnforceAccountPolicy(PolicyRule rule)
        {
            try
            {
                // Check if Guest account is enabled
                var output = RunCmd("net", "user Guest");
                if (output.Contains("Account active") && output.Contains("Yes"))
                {
                    if (rule.Action == PolicyAction.AutoFix || rule.Action == PolicyAction.Block)
                    {
                        RunCmd("net", "user Guest /active:no");
                        RecordViolation(rule, "Guest account was active - disabled by policy");
                    }
                    else
                    {
                        RecordViolation(rule, "Guest account is active");
                    }
                }
            }
            catch { }
        }

        private void EnforceScreenLockPolicy(PolicyRule rule)
        {
            try
            {
                // Check if screensaver with password is configured
                using var key = Registry.CurrentUser.OpenSubKey(
                    @"Control Panel\Desktop");
                if (key != null)
                {
                    var screensaverActive = key.GetValue("ScreenSaveActive")?.ToString() == "1";
                    var passwordProtected = key.GetValue("ScreenSaverIsSecure")?.ToString() == "1";
                    var timeout = key.GetValue("ScreenSaveTimeOut")?.ToString() ?? "0";
                    var timeoutSec = int.TryParse(timeout, out var t) ? t : 0;

                    if (!screensaverActive || !passwordProtected || timeoutSec == 0 || timeoutSec > 900)
                    {
                        RecordViolation(rule,
                            $"Screen lock not properly configured (active={screensaverActive}, secure={passwordProtected}, timeout={timeoutSec}s)");
                    }
                }
            }
            catch { }
        }

        // === Dashboard Sync ===

        private Task<ModuleResponse> HandleAddPolicy(ModuleCommand command)
        {
            var name = command.Parameters.GetValueOrDefault("name", "Custom Rule");
            var category = command.Parameters.GetValueOrDefault("category", "custom");
            var actionStr = command.Parameters.GetValueOrDefault("action", "Alert");

            if (!Enum.TryParse<PolicyAction>(actionStr, true, out var action))
                action = PolicyAction.Alert;

            var newRule = new PolicyRule
            {
                Id = $"custom_{DateTime.UtcNow.Ticks}",
                Name = name,
                Category = category,
                Action = action,
                Enabled = true,
                Parameters = command.Parameters
            };
            _rules.Add(newRule);
            SavePolicies();

            return Task.FromResult(ModuleResponse.Ok($"Policy '{name}' added", new Dictionary<string, object>
            {
                ["ruleId"] = newRule.Id
            }));
        }

        private Task<ModuleResponse> HandleDashboardSync(ModuleCommand command)
        {
            // Accept policies pushed from dashboard
            var rulesJson = command.Parameters.GetValueOrDefault("rules", "");
            if (!string.IsNullOrEmpty(rulesJson))
            {
                try
                {
                    var dashboardRules = JsonSerializer.Deserialize<List<PolicyRule>>(rulesJson,
                        new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                    if (dashboardRules != null)
                    {
                        // Replace dashboard-synced rules (keep built-in + local custom)
                        _rules.RemoveAll(r => r.Id.StartsWith("dash_"));
                        foreach (var r in dashboardRules)
                        {
                            r.Id = $"dash_{r.Id}";
                            _rules.Add(r);
                        }
                        _lastDashboardSync = DateTime.UtcNow;
                        SavePolicies();
                    }
                }
                catch { }
            }

            return Task.FromResult(ModuleResponse.Ok("Policies synced from dashboard"));
        }

        // === Helpers ===

        private void RecordViolation(PolicyRule rule, string detail)
        {
            // Deduplicate: don't record same violation within 5 minutes
            var recent = _violations.LastOrDefault(v =>
                v.RuleId == rule.Id && v.Detail == detail &&
                v.Timestamp > DateTime.UtcNow.AddMinutes(-5));
            if (recent != null) return;

            var violation = new PolicyViolation
            {
                RuleId = rule.Id,
                RuleName = rule.Name,
                Category = rule.Category,
                Action = rule.Action.ToString(),
                Detail = detail,
                Timestamp = DateTime.UtcNow
            };
            _violations.Add(violation);
            while (_violations.Count > 500) _violations.RemoveAt(0);

            if (rule.Action == PolicyAction.Alert || rule.Action == PolicyAction.Block)
            {
                _context.RaiseAlert(new Alert
                {
                    ModuleId = Id,
                    Title = $"Policy: {rule.Name}",
                    Message = detail,
                    Severity = rule.Action == PolicyAction.Block ? AlertSeverity.Warning : AlertSeverity.Info,
                    Category = "policy"
                });
            }

            _context.Log(LogLevel.Warning, Id, $"Policy violation: {rule.Name} - {detail}");
        }

        private static string RunCmd(string fileName, string arguments)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = fileName,
                    Arguments = arguments,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                };
                using var proc = Process.Start(psi);
                if (proc == null) return "";
                var output = proc.StandardOutput.ReadToEnd();
                proc.WaitForExit(10000);
                return output;
            }
            catch { return ""; }
        }
    }

    public class PolicyViolation
    {
        public string RuleId { get; set; } = "";
        public string RuleName { get; set; } = "";
        public string Category { get; set; } = "";
        public string Action { get; set; } = "";
        public string Detail { get; set; } = "";
        public DateTime Timestamp { get; set; }
    }
}
