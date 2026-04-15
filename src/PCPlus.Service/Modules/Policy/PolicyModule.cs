using System.Diagnostics;
using System.Management;
using Microsoft.Win32;
using PCPlus.Core.Interfaces;
using PCPlus.Core.Models;

namespace PCPlus.Service.Modules.Policy
{
    /// <summary>
    /// Policy enforcement module. Enforces security rules per client/device.
    /// USB blocking, PowerShell restriction, BitLocker enforcement.
    /// Custom rules from central dashboard.
    /// Premium tier.
    /// </summary>
    public class PolicyModule : IModule
    {
        public string Id => "policy";
        public string Name => "Policy Engine";
        public string Version => "4.0.0";
        public LicenseTier RequiredTier => LicenseTier.Premium;
        public bool IsRunning { get; private set; }

        private IModuleContext _context = null!;
        private Timer? _enforcementTimer;
        private readonly List<PolicyRule> _rules = new();
        private readonly List<string> _violations = new();

        public Task InitializeAsync(IModuleContext context)
        {
            _context = context;
            LoadPolicies();
            return Task.CompletedTask;
        }

        public Task StartAsync(CancellationToken cancellationToken)
        {
            IsRunning = true;
            // Enforce policies every 60 seconds
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
                        ["violations"] = _violations
                    }));

                case "AddPolicy":
                    // TODO: Add policy from dashboard
                    return Task.FromResult(ModuleResponse.Ok("Policy added"));

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
            StatusText = $"{_rules.Count(r => r.Enabled)} rules active",
            LastActivity = DateTime.UtcNow,
            Metrics = new()
            {
                ["activeRules"] = _rules.Count(r => r.Enabled),
                ["violations"] = _violations.Count
            }
        };

        private void LoadPolicies()
        {
            var cfg = _context.Config;

            // Built-in policies from config
            if (cfg.BlockUSB)
            {
                _rules.Add(new PolicyRule
                {
                    Id = "block_usb", Name = "Block USB Storage",
                    Category = "usb", Action = PolicyAction.Block, Enabled = true
                });
            }

            if (cfg.BlockPowerShell)
            {
                _rules.Add(new PolicyRule
                {
                    Id = "block_ps", Name = "Block PowerShell",
                    Category = "powershell", Action = PolicyAction.Block, Enabled = true
                });
            }

            if (cfg.EnforceBitLocker)
            {
                _rules.Add(new PolicyRule
                {
                    Id = "enforce_bitlocker", Name = "Enforce BitLocker",
                    Category = "bitlocker", Action = PolicyAction.Alert, Enabled = true
                });
            }

            // TODO: Load custom rules from dashboard API
        }

        private void EnforcePolicies()
        {
            foreach (var rule in _rules.Where(r => r.Enabled))
            {
                try
                {
                    switch (rule.Category)
                    {
                        case "usb":
                            EnforceUsbPolicy(rule);
                            break;
                        case "powershell":
                            EnforcePowerShellPolicy(rule);
                            break;
                        case "bitlocker":
                            EnforceBitLockerPolicy(rule);
                            break;
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
                // Disable USB mass storage via registry
                using var key = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Services\USBSTOR", true);
                if (key != null)
                {
                    var current = Convert.ToInt32(key.GetValue("Start", 3));
                    if (current != 4) // 4 = disabled
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

            // Kill any running PowerShell processes
            try
            {
                foreach (var proc in Process.GetProcessesByName("powershell"))
                {
                    proc.Kill();
                    RecordViolation(rule, $"PowerShell process killed (PID {proc.Id})");
                    proc.Dispose();
                }
                foreach (var proc in Process.GetProcessesByName("pwsh"))
                {
                    proc.Kill();
                    RecordViolation(rule, $"PowerShell Core killed (PID {proc.Id})");
                    proc.Dispose();
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
                        if (status != 1) // Not protected
                        {
                            RecordViolation(rule, $"BitLocker not active on {sysDrive}");
                        }
                    }
                }
            }
            catch { }
        }

        private void RecordViolation(PolicyRule rule, string detail)
        {
            _violations.Add($"[{DateTime.UtcNow:HH:mm:ss}] {rule.Name}: {detail}");
            while (_violations.Count > 100) _violations.RemoveAt(0);

            if (rule.Action == PolicyAction.Alert || rule.Action == PolicyAction.Block)
            {
                _context.RaiseAlert(new Alert
                {
                    ModuleId = Id,
                    Title = $"Policy Violation: {rule.Name}",
                    Message = detail,
                    Severity = AlertSeverity.Warning,
                    Category = "policy"
                });
            }

            _context.Log(LogLevel.Warning, Id, $"Policy violation: {rule.Name} - {detail}");
        }
    }
}
