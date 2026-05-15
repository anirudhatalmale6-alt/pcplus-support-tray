using System.Diagnostics;
using Microsoft.Win32;
using PCPlus.Core.Interfaces;

namespace PCPlus.Service.Modules.Ransomware
{
    /// <summary>
    /// Proactive system hardening - reduces attack surface BEFORE ransomware runs.
    /// Instead of waiting to detect and respond, this makes the system resistant
    /// to common ransomware techniques at the OS level.
    ///
    /// Hardening layers:
    /// 1. Attack Surface Reduction: Enable Windows ASR rules via registry
    /// 2. Controlled Folder Access: Windows built-in ransomware protection
    /// 3. Script Host Lockdown: Disable wscript/cscript (VBS/JS execution)
    /// 4. PowerShell Restriction: Constrained language mode for non-admin
    /// 5. SMBv1 Disable: Remove legacy protocol used for lateral movement
    /// 6. Macro Execution Policy: Block Office macros from internet
    /// 7. Executable Restriction: Block execution from temp/downloads
    /// 8. RDP Hardening: NLA required, brute force lockout
    /// 9. LSASS Protection: Credential dump prevention
    /// 10. Firewall Rules: Block unnecessary inbound connections
    ///
    /// All changes are tracked and reversible. Each hardening rule can be
    /// individually enabled/disabled via config or dashboard command.
    /// </summary>
    public class SystemHardening : IDisposable
    {
        private IModuleContext _context = null!;
        private Timer? _complianceTimer;
        private readonly List<HardeningRule> _rules = new();
        private readonly List<HardeningEvent> _events = new();
        private readonly object _lock = new();
        private bool _isActive;

        private static readonly string StateFile = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "PCPlusEndpoint", "ransomware", "hardening-state.json");

        public void Start(IModuleContext context)
        {
            _context = context;
            InitializeRules();
            ApplyAllHardening();

            // Compliance check every 10 minutes - re-apply if something reverts our changes
            _complianceTimer = new Timer(_ => ComplianceCheck(), null,
                TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(10));

            _isActive = true;
            _context.Log(LogLevel.Info, "ransomware",
                $"System Hardening active: {_rules.Count(r => r.Applied)} of {_rules.Count} rules applied");
        }

        public void Stop()
        {
            _isActive = false;
            _complianceTimer?.Dispose();
        }

        public HardeningStatus GetStatus()
        {
            lock (_lock)
            {
                return new HardeningStatus
                {
                    IsActive = _isActive,
                    TotalRules = _rules.Count,
                    AppliedRules = _rules.Count(r => r.Applied),
                    FailedRules = _rules.Count(r => r.Failed),
                    Rules = _rules.Select(r => new HardeningRuleSummary
                    {
                        Id = r.Id,
                        Name = r.Name,
                        Category = r.Category,
                        Applied = r.Applied,
                        Failed = r.Failed,
                        FailReason = r.FailReason
                    }).ToList(),
                    RecentEvents = _events.TakeLast(20).Reverse().ToList()
                };
            }
        }

        private void InitializeRules()
        {
            // --- Attack Surface Reduction (ASR) Rules ---
            // These are Windows Defender ASR GUIDs - enabled via registry

            _rules.Add(new HardeningRule
            {
                Id = "asr-office-child-process",
                Name = "Block Office apps from creating child processes",
                Category = "Attack Surface Reduction",
                Apply = () => SetAsrRule("D4F940AB-401B-4EFC-AADC-AD5F3C50688A", 1),
                Check = () => CheckAsrRule("D4F940AB-401B-4EFC-AADC-AD5F3C50688A"),
                Revert = () => SetAsrRule("D4F940AB-401B-4EFC-AADC-AD5F3C50688A", 0)
            });

            _rules.Add(new HardeningRule
            {
                Id = "asr-office-macro-code",
                Name = "Block Office apps from creating executable content",
                Category = "Attack Surface Reduction",
                Apply = () => SetAsrRule("3B576869-A4EC-4529-8536-B80A7769E899", 1),
                Check = () => CheckAsrRule("3B576869-A4EC-4529-8536-B80A7769E899"),
                Revert = () => SetAsrRule("3B576869-A4EC-4529-8536-B80A7769E899", 0)
            });

            _rules.Add(new HardeningRule
            {
                Id = "asr-script-obfuscation",
                Name = "Block execution of potentially obfuscated scripts",
                Category = "Attack Surface Reduction",
                Apply = () => SetAsrRule("5BEB7EFE-FD9A-4556-801D-275E5FFC04CC", 1),
                Check = () => CheckAsrRule("5BEB7EFE-FD9A-4556-801D-275E5FFC04CC"),
                Revert = () => SetAsrRule("5BEB7EFE-FD9A-4556-801D-275E5FFC04CC", 0)
            });

            _rules.Add(new HardeningRule
            {
                Id = "asr-js-vbs-launch",
                Name = "Block JavaScript/VBScript from launching downloaded content",
                Category = "Attack Surface Reduction",
                Apply = () => SetAsrRule("D3E037E1-3EB8-44C8-A917-57927947596D", 1),
                Check = () => CheckAsrRule("D3E037E1-3EB8-44C8-A917-57927947596D"),
                Revert = () => SetAsrRule("D3E037E1-3EB8-44C8-A917-57927947596D", 0)
            });

            _rules.Add(new HardeningRule
            {
                Id = "asr-email-executable",
                Name = "Block executable content from email and webmail",
                Category = "Attack Surface Reduction",
                Apply = () => SetAsrRule("BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550", 1),
                Check = () => CheckAsrRule("BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550"),
                Revert = () => SetAsrRule("BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550", 0)
            });

            _rules.Add(new HardeningRule
            {
                Id = "asr-wmi-persistence",
                Name = "Block process creation from WMI event subscription",
                Category = "Attack Surface Reduction",
                Apply = () => SetAsrRule("E6DB77E5-3DF2-4CF1-B95A-636979351E5B", 1),
                Check = () => CheckAsrRule("E6DB77E5-3DF2-4CF1-B95A-636979351E5B"),
                Revert = () => SetAsrRule("E6DB77E5-3DF2-4CF1-B95A-636979351E5B", 0)
            });

            _rules.Add(new HardeningRule
            {
                Id = "asr-credential-steal",
                Name = "Block credential stealing from LSASS",
                Category = "Attack Surface Reduction",
                Apply = () => SetAsrRule("9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2", 1),
                Check = () => CheckAsrRule("9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2"),
                Revert = () => SetAsrRule("9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2", 0)
            });

            _rules.Add(new HardeningRule
            {
                Id = "asr-ransomware-protection",
                Name = "Use advanced protection against ransomware",
                Category = "Attack Surface Reduction",
                Apply = () => SetAsrRule("C1DB55AB-C21A-4637-BB3F-A12568109D35", 1),
                Check = () => CheckAsrRule("C1DB55AB-C21A-4637-BB3F-A12568109D35"),
                Revert = () => SetAsrRule("C1DB55AB-C21A-4637-BB3F-A12568109D35", 0)
            });

            // --- Controlled Folder Access ---
            _rules.Add(new HardeningRule
            {
                Id = "controlled-folder-access",
                Name = "Enable Windows Controlled Folder Access (ransomware protection)",
                Category = "Controlled Folder Access",
                Apply = () =>
                {
                    RunPowerShell("Set-MpPreference -EnableControlledFolderAccess Enabled");
                    return true;
                },
                Check = () =>
                {
                    var output = RunPowerShellOutput("(Get-MpPreference).EnableControlledFolderAccess");
                    return output.Trim() == "1" || output.Trim().Equals("Enabled", StringComparison.OrdinalIgnoreCase);
                },
                Revert = () =>
                {
                    RunPowerShell("Set-MpPreference -EnableControlledFolderAccess Disabled");
                    return true;
                }
            });

            // --- Script Host Lockdown ---
            _rules.Add(new HardeningRule
            {
                Id = "disable-wscript",
                Name = "Disable Windows Script Host (blocks VBS/JS malware)",
                Category = "Script Restriction",
                Apply = () => SetRegistryValue(
                    Registry.LocalMachine,
                    @"SOFTWARE\Microsoft\Windows Script Host\Settings",
                    "Enabled", 0, RegistryValueKind.DWord),
                Check = () => GetRegistryValue(
                    Registry.LocalMachine,
                    @"SOFTWARE\Microsoft\Windows Script Host\Settings",
                    "Enabled") == 0,
                Revert = () => SetRegistryValue(
                    Registry.LocalMachine,
                    @"SOFTWARE\Microsoft\Windows Script Host\Settings",
                    "Enabled", 1, RegistryValueKind.DWord)
            });

            // --- PowerShell Hardening ---
            _rules.Add(new HardeningRule
            {
                Id = "ps-constrained-language",
                Name = "PowerShell Constrained Language Mode for non-admin users",
                Category = "Script Restriction",
                Apply = () => SetRegistryValue(
                    Registry.LocalMachine,
                    @"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
                    "__PSLockdownPolicy", 4, RegistryValueKind.DWord),
                Check = () => GetRegistryValue(
                    Registry.LocalMachine,
                    @"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
                    "__PSLockdownPolicy") == 4,
                Revert = () => DeleteRegistryValue(
                    Registry.LocalMachine,
                    @"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
                    "__PSLockdownPolicy")
            });

            _rules.Add(new HardeningRule
            {
                Id = "ps-logging",
                Name = "Enable PowerShell Script Block Logging",
                Category = "Script Restriction",
                Apply = () => SetRegistryValue(
                    Registry.LocalMachine,
                    @"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
                    "EnableScriptBlockLogging", 1, RegistryValueKind.DWord),
                Check = () => GetRegistryValue(
                    Registry.LocalMachine,
                    @"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
                    "EnableScriptBlockLogging") == 1,
                Revert = () => SetRegistryValue(
                    Registry.LocalMachine,
                    @"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
                    "EnableScriptBlockLogging", 0, RegistryValueKind.DWord)
            });

            // --- SMBv1 Disable ---
            _rules.Add(new HardeningRule
            {
                Id = "disable-smbv1",
                Name = "Disable SMBv1 (WannaCry/EternalBlue attack vector)",
                Category = "Network Hardening",
                Apply = () =>
                {
                    RunCmd("dism", "/online /norestart /disable-feature /featurename:SMB1Protocol");
                    SetRegistryValue(Registry.LocalMachine,
                        @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
                        "SMB1", 0, RegistryValueKind.DWord);
                    return true;
                },
                Check = () => GetRegistryValue(
                    Registry.LocalMachine,
                    @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
                    "SMB1") == 0,
                Revert = () => SetRegistryValue(
                    Registry.LocalMachine,
                    @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
                    "SMB1", 1, RegistryValueKind.DWord)
            });

            // --- RDP Hardening ---
            _rules.Add(new HardeningRule
            {
                Id = "rdp-nla",
                Name = "Require Network Level Authentication for RDP",
                Category = "Network Hardening",
                Apply = () => SetRegistryValue(
                    Registry.LocalMachine,
                    @"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
                    "UserAuthentication", 1, RegistryValueKind.DWord),
                Check = () => GetRegistryValue(
                    Registry.LocalMachine,
                    @"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
                    "UserAuthentication") == 1,
                Revert = () => SetRegistryValue(
                    Registry.LocalMachine,
                    @"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
                    "UserAuthentication", 0, RegistryValueKind.DWord)
            });

            _rules.Add(new HardeningRule
            {
                Id = "rdp-lockout",
                Name = "Account lockout after 5 failed RDP attempts (30 min)",
                Category = "Network Hardening",
                Apply = () =>
                {
                    RunCmd("net", "accounts /lockoutthreshold:5 /lockoutwindow:30 /lockoutduration:30");
                    return true;
                },
                Check = () =>
                {
                    var output = RunCmdOutput("net", "accounts");
                    return output.Contains("5") && output.Contains("Lockout threshold");
                },
                Revert = () =>
                {
                    RunCmd("net", "accounts /lockoutthreshold:0");
                    return true;
                }
            });

            // --- LSASS Protection ---
            _rules.Add(new HardeningRule
            {
                Id = "lsass-protection",
                Name = "Enable LSASS process protection (credential dump prevention)",
                Category = "Credential Protection",
                Apply = () => SetRegistryValue(
                    Registry.LocalMachine,
                    @"SYSTEM\CurrentControlSet\Control\Lsa",
                    "RunAsPPL", 1, RegistryValueKind.DWord),
                Check = () => GetRegistryValue(
                    Registry.LocalMachine,
                    @"SYSTEM\CurrentControlSet\Control\Lsa",
                    "RunAsPPL") == 1,
                Revert = () => SetRegistryValue(
                    Registry.LocalMachine,
                    @"SYSTEM\CurrentControlSet\Control\Lsa",
                    "RunAsPPL", 0, RegistryValueKind.DWord)
            });

            // --- Macro Policy ---
            _rules.Add(new HardeningRule
            {
                Id = "office-macro-block",
                Name = "Block macros from internet-sourced Office documents",
                Category = "Application Hardening",
                Apply = () =>
                {
                    // Office 2016/2019/365 - all apps
                    foreach (var app in new[] { "Word", "Excel", "PowerPoint" })
                    {
                        SetRegistryValue(Registry.LocalMachine,
                            $@"SOFTWARE\Policies\Microsoft\Office\16.0\{app.ToLower()}\security",
                            "blockcontentexecutionfrominternet", 1, RegistryValueKind.DWord);
                    }
                    return true;
                },
                Check = () => GetRegistryValue(
                    Registry.LocalMachine,
                    @"SOFTWARE\Policies\Microsoft\Office\16.0\word\security",
                    "blockcontentexecutionfrominternet") == 1,
                Revert = () =>
                {
                    foreach (var app in new[] { "Word", "Excel", "PowerPoint" })
                    {
                        DeleteRegistryValue(Registry.LocalMachine,
                            $@"SOFTWARE\Policies\Microsoft\Office\16.0\{app.ToLower()}\security",
                            "blockcontentexecutionfrominternet");
                    }
                    return true;
                }
            });

            // --- Block execution from risky paths ---
            _rules.Add(new HardeningRule
            {
                Id = "block-temp-execution",
                Name = "Block executable launch from Temp/Downloads via Software Restriction",
                Category = "Application Hardening",
                Apply = () =>
                {
                    // Use Software Restriction Policies (SRP) via registry
                    var paths = new[]
                    {
                        @"%USERPROFILE%\AppData\Local\Temp\*.exe",
                        @"%USERPROFILE%\Downloads\*.exe",
                        @"%TEMP%\*.exe",
                    };
                    foreach (var path in paths)
                    {
                        var hash = path.GetHashCode().ToString("x8");
                        SetRegistryValue(Registry.LocalMachine,
                            $@"SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\Paths\{{{hash}}}",
                            "ItemData", path, RegistryValueKind.ExpandString);
                        SetRegistryValue(Registry.LocalMachine,
                            $@"SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\Paths\{{{hash}}}",
                            "SaferFlags", 0, RegistryValueKind.DWord);
                    }
                    // Enable SRP
                    SetRegistryValue(Registry.LocalMachine,
                        @"SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers",
                        "DefaultLevel", 262144, RegistryValueKind.DWord);
                    SetRegistryValue(Registry.LocalMachine,
                        @"SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers",
                        "TransparentEnabled", 1, RegistryValueKind.DWord);
                    return true;
                },
                Check = () => GetRegistryValue(
                    Registry.LocalMachine,
                    @"SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers",
                    "TransparentEnabled") == 1,
                Revert = () =>
                {
                    try
                    {
                        Registry.LocalMachine.DeleteSubKeyTree(
                            @"SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\Paths", false);
                    }
                    catch { }
                    DeleteRegistryValue(Registry.LocalMachine,
                        @"SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers",
                        "TransparentEnabled");
                    return true;
                }
            });

            // --- Windows Firewall: block inbound by default ---
            _rules.Add(new HardeningRule
            {
                Id = "firewall-inbound-block",
                Name = "Windows Firewall: block all inbound by default",
                Category = "Network Hardening",
                Apply = () =>
                {
                    RunCmd("netsh", "advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound");
                    return true;
                },
                Check = () =>
                {
                    var output = RunCmdOutput("netsh", "advfirewall show allprofiles firewallpolicy");
                    return output.Contains("BlockInbound", StringComparison.OrdinalIgnoreCase);
                },
                Revert = () =>
                {
                    RunCmd("netsh", "advfirewall set allprofiles firewallpolicy allowinbound,allowoutbound");
                    return true;
                }
            });

            // --- Disable AutoRun/AutoPlay ---
            _rules.Add(new HardeningRule
            {
                Id = "disable-autorun",
                Name = "Disable AutoRun/AutoPlay (USB malware vector)",
                Category = "Application Hardening",
                Apply = () =>
                {
                    SetRegistryValue(Registry.LocalMachine,
                        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
                        "NoDriveTypeAutoRun", 255, RegistryValueKind.DWord);
                    SetRegistryValue(Registry.LocalMachine,
                        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
                        "NoAutorun", 1, RegistryValueKind.DWord);
                    return true;
                },
                Check = () => GetRegistryValue(
                    Registry.LocalMachine,
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
                    "NoDriveTypeAutoRun") == 255,
                Revert = () =>
                {
                    DeleteRegistryValue(Registry.LocalMachine,
                        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
                        "NoDriveTypeAutoRun");
                    DeleteRegistryValue(Registry.LocalMachine,
                        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
                        "NoAutorun");
                    return true;
                }
            });
        }

        private void ApplyAllHardening()
        {
            int applied = 0, failed = 0;
            foreach (var rule in _rules)
            {
                try
                {
                    if (rule.Check())
                    {
                        rule.Applied = true;
                        applied++;
                        continue;
                    }

                    var result = rule.Apply();
                    rule.Applied = result;
                    if (result)
                    {
                        applied++;
                        RecordEvent("applied", rule.Id, $"Hardening rule applied: {rule.Name}");
                        _context.Log(LogLevel.Info, "ransomware", $"Hardening: Applied '{rule.Name}'");
                    }
                    else
                    {
                        rule.Failed = true;
                        rule.FailReason = "Apply returned false";
                        failed++;
                    }
                }
                catch (Exception ex)
                {
                    rule.Failed = true;
                    rule.FailReason = ex.Message;
                    failed++;
                    _context.Log(LogLevel.Warning, "ransomware",
                        $"Hardening: Failed to apply '{rule.Name}': {ex.Message}");
                }
            }

            _context.Log(LogLevel.Info, "ransomware",
                $"System Hardening: {applied} rules applied, {failed} failed, {_rules.Count} total");
        }

        private void ComplianceCheck()
        {
            foreach (var rule in _rules.Where(r => r.Applied && !r.Failed))
            {
                try
                {
                    if (!rule.Check())
                    {
                        _context.Log(LogLevel.Warning, "ransomware",
                            $"Hardening drift: '{rule.Name}' was reverted externally. Reapplying.");
                        rule.Apply();
                        RecordEvent("reapplied", rule.Id, $"Hardening rule was reverted externally and reapplied: {rule.Name}");

                        _context.RaiseAlert(new PCPlus.Core.Models.Alert
                        {
                            ModuleId = "ransomware",
                            Title = "Security Hardening Tampered",
                            Message = $"The hardening rule '{rule.Name}' was reverted by an external process. It has been reapplied automatically.",
                            Severity = PCPlus.Core.Models.AlertSeverity.Warning,
                            Category = "ransomware"
                        });
                    }
                }
                catch { }
            }
        }

        /// <summary>Apply a single rule by ID (from dashboard command).</summary>
        public bool ApplyRule(string ruleId)
        {
            var rule = _rules.FirstOrDefault(r => r.Id == ruleId);
            if (rule == null) return false;
            try
            {
                rule.Applied = rule.Apply();
                rule.Failed = !rule.Applied;
                return rule.Applied;
            }
            catch (Exception ex)
            {
                rule.Failed = true;
                rule.FailReason = ex.Message;
                return false;
            }
        }

        /// <summary>Revert a single rule by ID.</summary>
        public bool RevertRule(string ruleId)
        {
            var rule = _rules.FirstOrDefault(r => r.Id == ruleId);
            if (rule == null) return false;
            try
            {
                rule.Revert();
                rule.Applied = false;
                return true;
            }
            catch { return false; }
        }

        #region Registry Helpers

        private static bool SetRegistryValue(RegistryKey root, string path, string name, object value, RegistryValueKind kind)
        {
            using var key = root.CreateSubKey(path, writable: true);
            key?.SetValue(name, value, kind);
            return key != null;
        }

        private static int GetRegistryValue(RegistryKey root, string path, string name)
        {
            try
            {
                using var key = root.OpenSubKey(path);
                var val = key?.GetValue(name);
                return val is int i ? i : -1;
            }
            catch { return -1; }
        }

        private static bool DeleteRegistryValue(RegistryKey root, string path, string name)
        {
            try
            {
                using var key = root.OpenSubKey(path, writable: true);
                key?.DeleteValue(name, throwOnMissingValue: false);
                return true;
            }
            catch { return false; }
        }

        #endregion

        #region Command Helpers

        private static bool SetAsrRule(string guid, int action)
        {
            RunPowerShell($"Add-MpPreference -AttackSurfaceReductionRules_Ids {guid} -AttackSurfaceReductionRules_Actions {action}");
            return true;
        }

        private static bool CheckAsrRule(string guid)
        {
            var output = RunPowerShellOutput(
                $"(Get-MpPreference).AttackSurfaceReductionRules_Ids -contains '{guid}'");
            return output.Trim().Equals("True", StringComparison.OrdinalIgnoreCase);
        }

        private static void RunPowerShell(string command)
        {
            var psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-NoProfile -NonInteractive -Command \"{command}\"",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true
            };
            using var proc = Process.Start(psi);
            proc?.WaitForExit(15000);
        }

        private static string RunPowerShellOutput(string command)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-NoProfile -NonInteractive -Command \"{command}\"",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true
                };
                using var proc = Process.Start(psi);
                var output = proc?.StandardOutput.ReadToEnd() ?? "";
                proc?.WaitForExit(15000);
                return output;
            }
            catch { return ""; }
        }

        private static void RunCmd(string fileName, string arguments)
        {
            var psi = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true
            };
            using var proc = Process.Start(psi);
            proc?.WaitForExit(30000);
        }

        private static string RunCmdOutput(string fileName, string arguments)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = fileName,
                    Arguments = arguments,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true
                };
                using var proc = Process.Start(psi);
                var output = proc?.StandardOutput.ReadToEnd() ?? "";
                proc?.WaitForExit(15000);
                return output;
            }
            catch { return ""; }
        }

        #endregion

        private void RecordEvent(string type, string ruleId, string detail)
        {
            lock (_lock)
            {
                _events.Add(new HardeningEvent
                {
                    Type = type,
                    RuleId = ruleId,
                    Detail = detail,
                    Timestamp = DateTime.UtcNow
                });
                if (_events.Count > 500)
                    _events.RemoveRange(0, _events.Count - 250);
            }
        }

        public void Dispose()
        {
            Stop();
        }
    }

    public class HardeningRule
    {
        public string Id { get; set; } = "";
        public string Name { get; set; } = "";
        public string Category { get; set; } = "";
        public Func<bool> Apply { get; set; } = () => false;
        public Func<bool> Check { get; set; } = () => false;
        public Func<bool> Revert { get; set; } = () => false;
        public bool Applied { get; set; }
        public bool Failed { get; set; }
        public string FailReason { get; set; } = "";
    }

    public class HardeningStatus
    {
        public bool IsActive { get; set; }
        public int TotalRules { get; set; }
        public int AppliedRules { get; set; }
        public int FailedRules { get; set; }
        public List<HardeningRuleSummary> Rules { get; set; } = new();
        public List<HardeningEvent> RecentEvents { get; set; } = new();
    }

    public class HardeningRuleSummary
    {
        public string Id { get; set; } = "";
        public string Name { get; set; } = "";
        public string Category { get; set; } = "";
        public bool Applied { get; set; }
        public bool Failed { get; set; }
        public string FailReason { get; set; } = "";
    }

    public class HardeningEvent
    {
        public string Type { get; set; } = "";
        public string RuleId { get; set; } = "";
        public string Detail { get; set; } = "";
        public DateTime Timestamp { get; set; }
    }
}
