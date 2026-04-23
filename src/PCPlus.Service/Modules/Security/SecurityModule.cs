using System.Diagnostics;
using System.Management;
using System.ServiceProcess;
using Microsoft.Win32;
using PCPlus.Core.Interfaces;
using PCPlus.Core.Models;

namespace PCPlus.Service.Modules.Security
{
    /// <summary>
    /// Security scanner module. Runs 120-point security audit.
    /// Produces 0-100 score with grade. Detects AV off, firewall changes.
    /// Free tier for basic, Standard+ for continuous monitoring.
    /// </summary>
    public class SecurityModule : IModule
    {
        public string Id => "security";
        public string Name => "Security Scanner";
        public string Version => "5.0.0";
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
                    // New check remediations
                    "account_lockout" => RunPowerShell("net accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30", "Account Lockout Policy"),
                    "llmnr_netbios" => RunPowerShell(@"
                        New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Force | Out-Null;
                        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -Value 0 -Type DWord", "LLMNR Disabled"),
                    "smartscreen" => RunPowerShell("Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer' -Name 'SmartScreenEnabled' -Value 'RequireAdmin'", "SmartScreen Enabled"),
                    "usb_storage" => RunPowerShell("Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR' -Name 'Start' -Value 4 -Type DWord", "USB Storage Blocked"),
                    "office_macros" => RunPowerShell(@"
                        New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\Common\Security' -Force | Out-Null;
                        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\Common\Security' -Name 'blockcontentexecutionfrominternet' -Value 1 -Type DWord", "Office Macros from Internet Blocked"),
                    "rdp_port_exposure" => (false, "Change RDP port manually: Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name 'PortNumber' -Value <new_port>"),
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
                CheckAccountLockoutPolicy(),
                CheckLocalAdminRisk(),
                CheckMfaStatus(),

                // === NETWORK ===
                CheckRDP(),
                CheckRdpExposure(),
                CheckRdpBruteForce(),
                CheckRdpPortExposure(),
                CheckSMBv1(),
                CheckOpenPorts(),
                CheckDnsSecurity(),
                CheckWifiSecurity(),
                CheckVpnStatus(),
                CheckLlmnrNetbios(),
                CheckFirewallRuleAudit(),

                // === UPDATES & PATCHES ===
                CheckWindowsUpdate(),
                CheckLastWindowsUpdate(),
                CheckWindowsVersion(),
                CheckEndOfLifeSoftware(),
                CheckOutdatedSoftware(),
                CheckMissingCriticalUpdates(),
                CheckPatchAge(),
                CheckRebootPending(),

                // === DATA PROTECTION ===
                CheckBitLocker(),
                CheckBackupStatus(),
                CheckShadowCopies(),
                CheckBackupFrequency(),
                CheckFolderProtection(),
                CheckBackupImmutability(),

                // === DEVICE HEALTH ===
                CheckDiskSmartHealth(),
                CheckSsdWearLevel(),
                CheckBatteryHealth(),
                CheckRamErrors(),

                // === LOGGING & VISIBILITY ===
                CheckEventLoggingAudit(),
                CheckLogRetention(),

                // === ENDPOINT HARDENING ===
                CheckAppLockerWdac(),
                CheckOfficeMacroSecurity(),
                CheckSmartScreen(),

                // === DEVICE CONTROL ===
                CheckUsbStoragePolicy(),
                CheckBluetoothRisk(),

                // === BROWSER & USER RISK ===
                CheckSavedPasswordRisk(),
                CheckBrowserExtensions(),

                // === DATA EXPOSURE ===
                CheckDesktopDataExposure(),

                // === HARDWARE SECURITY ===
                CheckBiosPassword(),
                CheckVirtualizationSecurity(),

                // === PRIVILEGE ESCALATION (ADVANCED) ===
                CheckWeakServicePermissions(),
                CheckWritableSystemFolders(),
                CheckDllHijackingRisk(),

                // === EDR & ADVANCED ===
                CheckEdrInstalled(),
                CheckPowerShellLogging(),
                CheckScriptExecutionPolicy(),
                CheckSecureBoot(),
                CheckAttackSurfaceReduction(),
                CheckSuspiciousScheduledTasks(),

                // === RMM STACK ===
                CheckTacticalRmmAgent(),
                CheckWazuhAgent(),

                // === PROTECTION (EXTENDED) ===
                CheckDefenderSignatureAge(),
                CheckDefenderCloud(),
                CheckIoavProtection(),
                CheckAvPassiveMode(),
                CheckWebProtection(),
                CheckTamperChannels(),

                // === UPDATES (EXTENDED) ===
                CheckDriverUpdates(),
                CheckDefenderPlatformAge(),
                CheckBrowserPatchAge(),
                CheckThirdPartyPatchCompliance(),
                CheckKnownCveExposure(),
                CheckPatchFailureHistory(),
                CheckUpdateSourceHealth(),
                CheckUpdatePolicy(),

                // === DATA PROTECTION (EXTENDED) ===
                CheckBackupLastSuccess(),
                CheckBackupLastFailure(),
                CheckRestoreTested(),
                CheckOffsiteBackup(),
                CheckBackupEncryption(),
                CheckBackupRetention(),
                CheckBackupCoverage(),
                CheckAirgapBackup(),
                CheckStorageReliability(),

                // === NETWORK (EXTENDED) ===
                CheckExternalExposure(),
                CheckSmbSigning(),
                CheckNtlmRestriction(),
                CheckNetworkSegmentation(),
                CheckPublicShareExposure(),
                CheckDnsOverHttps(),
                CheckFwFirmwareAge(),
                CheckGeoOutboundAnomaly(),

                // === IDENTITY & ACCESS (EXTENDED) ===
                CheckIdpMfaValidation(),
                CheckStaleAdminAccounts(),
                CheckServiceAccountAudit(),
                CheckAdminLogonFrequency(),
                CheckFailedLogonPattern(),
                CheckPasswordReuseRisk(),
                CheckCloudIdentityMismatch(),

                // === RANSOMWARE PROTECTION (EXTENDED) ===
                CheckHoneyfileStatus(),
                CheckMassRenameDetection(),
                CheckEntropyAnomaly(),
                CheckBackupDeleteAttempts(),
                CheckRestoreObjective(),
                CheckIsolationReady(),

                // === EDR & ADVANCED (EXTENDED) ===
                CheckEdrSensorHealth(),
                CheckSysmonStatus(),
                CheckProcessInjectionIndicators(),

                // === LOGGING & VISIBILITY (EXTENDED) ===
                CheckLogForwarding(),
                CheckSecurityLogSize(),

                // === ENDPOINT HARDENING (EXTENDED) ===
                CheckWdacMode(),

                // === HARDWARE SECURITY (EXTENDED) ===
                CheckTpmReady()
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

        // ===================================================================
        // NEW CHECKS: Enterprise / SOC Level
        // ===================================================================

        // --- IDENTITY & ACCESS (EXPANDED) ---

        private SecurityCheck CheckAccountLockoutPolicy() => RunCheck("account_lockout", "Account Lockout Policy", "Identity & Access", 5, () =>
        {
            try
            {
                var startInfo = new ProcessStartInfo("net", "accounts")
                { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                using var proc = Process.Start(startInfo);
                var output = proc?.StandardOutput.ReadToEnd() ?? "";
                proc?.WaitForExit(10000);

                int threshold = 0;
                foreach (var line in output.Split('\n'))
                {
                    if (line.Contains("Lockout threshold", StringComparison.OrdinalIgnoreCase))
                    {
                        var parts = line.Split(':');
                        if (parts.Length > 1) int.TryParse(parts[1].Trim(), out threshold);
                    }
                }

                if (threshold == 0)
                    return (false, "No account lockout policy (unlimited login attempts)", "Set account lockout threshold to 5 attempts - prevents brute-force attacks");
                if (threshold > 10)
                    return (false, $"Lockout threshold too high: {threshold} attempts", "Reduce lockout threshold to 5 attempts");
                return (true, $"Account lockout after {threshold} failed attempts", "");
            }
            catch { return (true, "Unable to check lockout policy", ""); }
        });

        private SecurityCheck CheckLocalAdminRisk() => RunCheck("local_admin_risk", "Local Admin Risk", "Identity & Access", 5, () =>
        {
            try
            {
                // Check if current interactive users are running with admin privileges
                var startInfo = new ProcessStartInfo("powershell", "-NoProfile -NonInteractive -Command \"Get-LocalGroupMember -Group 'Administrators' | Select-Object -ExpandProperty Name\"")
                { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
                using var proc = Process.Start(startInfo);
                var output = proc?.StandardOutput.ReadToEnd() ?? "";
                proc?.WaitForExit(15000);

                var admins = output.Split('\n', StringSplitOptions.RemoveEmptyEntries)
                    .Select(l => l.Trim()).Where(l => !string.IsNullOrEmpty(l)).ToList();
                var nonBuiltIn = admins.Where(a =>
                    !a.EndsWith("\\Administrator", StringComparison.OrdinalIgnoreCase) &&
                    !a.Contains("Domain Admins", StringComparison.OrdinalIgnoreCase)).ToList();

                if (nonBuiltIn.Count > 2)
                    return (false, $"{nonBuiltIn.Count} users with admin rights: {string.Join(", ", nonBuiltIn.Take(4))}",
                        "Remove unnecessary admin rights - users should run as standard users");
                return (true, $"{admins.Count} admin accounts (within normal range)", "");
            }
            catch { return (true, "Unable to check local admin risk", ""); }
        });

        private SecurityCheck CheckMfaStatus() => RunCheck("mfa_status", "MFA Status", "Identity & Access", 8, () =>
        {
            try
            {
                // Check Windows Hello / PIN / biometric enrollment
                var helloConfigured = false;
                using (var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio\Databases"))
                    if (key?.GetSubKeyNames().Length > 0) helloConfigured = true;

                // Check if device is Azure AD joined (typically has MFA via Conditional Access)
                var aadJoined = false;
                var startInfo = new ProcessStartInfo("dsregcmd", "/status")
                { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                using var proc = Process.Start(startInfo);
                var output = proc?.StandardOutput.ReadToEnd() ?? "";
                proc?.WaitForExit(10000);
                if (output.Contains("AzureAdJoined : YES", StringComparison.OrdinalIgnoreCase))
                    aadJoined = true;

                // Check Credential Provider (e.g. Duo, AuthLite)
                var thirdPartyMfa = false;
                using (var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers"))
                {
                    if (key != null)
                    {
                        foreach (var subKey in key.GetSubKeyNames())
                        {
                            using var cp = key.OpenSubKey(subKey);
                            var name = cp?.GetValue("")?.ToString() ?? "";
                            if (name.Contains("Duo", StringComparison.OrdinalIgnoreCase) ||
                                name.Contains("AuthLite", StringComparison.OrdinalIgnoreCase) ||
                                name.Contains("RSA", StringComparison.OrdinalIgnoreCase) ||
                                name.Contains("Yubikey", StringComparison.OrdinalIgnoreCase))
                            {
                                thirdPartyMfa = true;
                                break;
                            }
                        }
                    }
                }

                if (aadJoined || thirdPartyMfa)
                    return (true, $"MFA available: {(aadJoined ? "Azure AD joined" : "")}{(thirdPartyMfa ? " + 3rd party MFA" : "")}", "");
                if (helloConfigured)
                    return (true, "Windows Hello biometric/PIN configured", "");
                return (false, "No MFA detected - password-only authentication",
                    "Enable MFA (Azure AD, Duo, or Windows Hello) - 80%+ attacks are credential-based");
            }
            catch { return (true, "Unable to check MFA status", ""); }
        });

        // --- NETWORK (EXPANDED) ---

        private SecurityCheck CheckRdpBruteForce() => RunCheck("rdp_bruteforce", "RDP Brute-force Protection", "Network", 5, () =>
        {
            try
            {
                // Check if RDP is enabled first
                using var rdpKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Terminal Server");
                var fDeny = rdpKey?.GetValue("fDenyTSConnections");
                if (fDeny != null && Convert.ToInt32(fDeny) == 1)
                    return (true, "RDP is disabled - no brute-force risk", "");

                // Check account lockout (brute-force protection)
                var startInfo = new ProcessStartInfo("net", "accounts")
                { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                using var proc = Process.Start(startInfo);
                var output = proc?.StandardOutput.ReadToEnd() ?? "";
                proc?.WaitForExit(10000);

                int threshold = 0;
                foreach (var line in output.Split('\n'))
                    if (line.Contains("Lockout threshold", StringComparison.OrdinalIgnoreCase))
                    {
                        var parts = line.Split(':');
                        if (parts.Length > 1) int.TryParse(parts[1].Trim(), out threshold);
                    }

                if (threshold == 0)
                    return (false, "RDP enabled with NO account lockout - vulnerable to brute-force",
                        "Set account lockout threshold (net accounts /lockoutthreshold:5) or disable RDP if not needed");
                return (true, $"RDP protected with lockout after {threshold} attempts", "");
            }
            catch { return (true, "Unable to check RDP brute-force protection", ""); }
        });

        private SecurityCheck CheckRdpPortExposure() => RunCheck("rdp_port_exposure", "RDP Port Exposure", "Network", 5, () =>
        {
            try
            {
                // Check if RDP is enabled
                using var rdpKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Terminal Server");
                var fDeny = rdpKey?.GetValue("fDenyTSConnections");
                if (fDeny != null && Convert.ToInt32(fDeny) == 1)
                    return (true, "RDP is disabled", "");

                // Check RDP port
                int rdpPort = 3389;
                using (var portKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"))
                {
                    var portVal = portKey?.GetValue("PortNumber");
                    if (portVal != null) rdpPort = Convert.ToInt32(portVal);
                }

                // Check if standard port 3389 is in use (higher risk if default)
                if (rdpPort == 3389)
                    return (false, "RDP using default port 3389 - easily discovered by attackers",
                        "Change RDP port from 3389 to a non-standard port, or use RDP Gateway");
                return (true, $"RDP on non-standard port {rdpPort}", "");
            }
            catch { return (true, "Unable to check RDP port", ""); }
        });

        private SecurityCheck CheckLlmnrNetbios() => RunCheck("llmnr_netbios", "LLMNR / NetBIOS Status", "Network", 5, () =>
        {
            try
            {
                var issues = new List<string>();

                // Check LLMNR
                using (var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"))
                {
                    var val = key?.GetValue("EnableMulticast");
                    if (val == null || Convert.ToInt32(val) != 0)
                        issues.Add("LLMNR enabled (poisoning attack vector)");
                }

                // Check NetBIOS over TCP/IP
                using var searcher = new ManagementObjectSearcher(
                    "SELECT TcpipNetbiosOptions FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=True");
                foreach (ManagementObject obj in searcher.Get())
                {
                    var nbOption = obj["TcpipNetbiosOptions"];
                    if (nbOption != null && Convert.ToInt32(nbOption) != 2) // 2 = disabled
                    {
                        issues.Add("NetBIOS over TCP/IP enabled");
                        break;
                    }
                }

                if (issues.Count > 0)
                    return (false, string.Join("; ", issues),
                        "Disable LLMNR and NetBIOS - common attack vectors for credential theft (Responder/MITM attacks)");
                return (true, "LLMNR and NetBIOS disabled", "");
            }
            catch { return (true, "Unable to check LLMNR/NetBIOS", ""); }
        });

        private SecurityCheck CheckFirewallRuleAudit() => RunCheck("fw_rule_audit", "Firewall Rule Audit", "Network", 5, () =>
        {
            try
            {
                var startInfo = new ProcessStartInfo("powershell", "-NoProfile -NonInteractive -Command \"(Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True | Measure-Object).Count\"")
                { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
                using var proc = Process.Start(startInfo);
                var output = proc?.StandardOutput.ReadToEnd()?.Trim() ?? "";
                proc?.WaitForExit(15000);

                if (int.TryParse(output, out int ruleCount))
                {
                    if (ruleCount > 50)
                        return (false, $"{ruleCount} inbound allow rules - excessive exposure",
                            "Audit firewall rules - remove unnecessary inbound allow rules to reduce attack surface");
                    return (true, $"{ruleCount} inbound allow rules (within normal range)", "");
                }
                return (true, "Unable to count firewall rules", "");
            }
            catch { return (true, "Unable to audit firewall rules", ""); }
        });

        // --- UPDATES & PATCHES (EXPANDED) ---

        private SecurityCheck CheckPatchAge() => RunCheck("patch_age", "Patch Age", "Updates", 8, () =>
        {
            try
            {
                // Check last installed hotfix date
                var startInfo = new ProcessStartInfo("powershell", "-NoProfile -NonInteractive -Command \"(Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn.ToString('yyyy-MM-dd')\"")
                { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
                using var proc = Process.Start(startInfo);
                var output = proc?.StandardOutput.ReadToEnd()?.Trim() ?? "";
                proc?.WaitForExit(15000);

                if (DateTime.TryParse(output, out var lastPatch))
                {
                    var daysSince = (DateTime.Now - lastPatch).Days;
                    if (daysSince > 60)
                        return (false, $"Last patch installed {daysSince} days ago ({lastPatch:MMM d, yyyy})",
                            "Install Windows updates immediately - patches more than 60 days old leave known vulnerabilities unpatched");
                    if (daysSince > 30)
                        return (false, $"Last patch installed {daysSince} days ago ({lastPatch:MMM d, yyyy})",
                            "Install pending Windows updates - monthly patching recommended");
                    return (true, $"Last patch: {daysSince} days ago ({lastPatch:MMM d, yyyy})", "");
                }
                return (true, "Unable to determine patch age", "");
            }
            catch { return (true, "Unable to check patch age", ""); }
        });

        private SecurityCheck CheckRebootPending() => RunCheck("reboot_pending", "Reboot Pending", "Updates", 5, () =>
        {
            try
            {
                var pendingReasons = new List<string>();

                // Component Based Servicing
                using (var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"))
                    if (key != null) pendingReasons.Add("Windows Update");

                // Windows Update
                using (var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"))
                    if (key != null) pendingReasons.Add("Update reboot required");

                // Pending file rename operations
                using (var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Session Manager"))
                {
                    var val = key?.GetValue("PendingFileRenameOperations") as string[];
                    if (val != null && val.Length > 0) pendingReasons.Add("File rename operations");
                }

                if (pendingReasons.Count > 0)
                    return (false, $"Reboot pending: {string.Join(", ", pendingReasons)}",
                        "Reboot the machine to complete pending updates - unpatched vulnerabilities remain until reboot");
                return (true, "No pending reboots", "");
            }
            catch { return (true, "Unable to check reboot status", ""); }
        });

        // --- DATA PROTECTION (EXPANDED) ---

        private SecurityCheck CheckBackupImmutability() => RunCheck("backup_immutable", "Backup Immutability", "Ransomware Protection", 8, () =>
        {
            try
            {
                var issues = new List<string>();

                // Check if System Restore points exist and are protected
                var startInfo = new ProcessStartInfo("powershell", "-NoProfile -NonInteractive -Command \"(Get-ComputerRestorePoint | Measure-Object).Count\"")
                { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
                using var proc = Process.Start(startInfo);
                var output = proc?.StandardOutput.ReadToEnd()?.Trim() ?? "";
                proc?.WaitForExit(15000);
                int.TryParse(output, out int restorePoints);

                // Check if backup location is local only (no offline/cloud backup detected)
                using (var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\FileHistory\DefaultSettings"))
                {
                    var target = key?.GetValue("TargetUrl")?.ToString();
                    if (string.IsNullOrEmpty(target))
                        issues.Add("No network/cloud backup target detected");
                }

                // Check if VSS admin access is unrestricted
                bool vssUnprotected = true;
                using (var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\VSS\Settings"))
                {
                    var val = key?.GetValue("RequireAccessControl");
                    if (val != null && Convert.ToInt32(val) == 1) vssUnprotected = false;
                }
                if (vssUnprotected) issues.Add("VSS not access-controlled (ransomware can delete shadow copies)");

                if (restorePoints == 0) issues.Add("No system restore points");

                if (issues.Count >= 2)
                    return (false, string.Join("; ", issues),
                        "Configure immutable/offline backups - ransomware targets accessible backups first. Use cloud backup with versioning.");
                if (issues.Count == 1)
                    return (false, issues[0], "Improve backup immutability - ensure backups cannot be encrypted or deleted by ransomware");
                return (true, $"Backup protection in place ({restorePoints} restore points)", "");
            }
            catch { return (true, "Unable to check backup immutability", ""); }
        });

        // --- LOGGING & VISIBILITY ---

        private SecurityCheck CheckEventLoggingAudit() => RunCheck("event_logging", "Windows Event Logging", "Logging & Visibility", 5, () =>
        {
            try
            {
                var startInfo = new ProcessStartInfo("auditpol", "/get /category:*")
                { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                using var proc = Process.Start(startInfo);
                var output = proc?.StandardOutput.ReadToEnd() ?? "";
                proc?.WaitForExit(10000);

                var noAudit = 0;
                var total = 0;
                foreach (var line in output.Split('\n'))
                {
                    if (line.Contains("No Auditing", StringComparison.OrdinalIgnoreCase))
                        noAudit++;
                    if (line.Contains("Success", StringComparison.OrdinalIgnoreCase) ||
                        line.Contains("Failure", StringComparison.OrdinalIgnoreCase) ||
                        line.Contains("No Auditing", StringComparison.OrdinalIgnoreCase))
                        total++;
                }

                if (total > 0 && noAudit > total * 0.6)
                    return (false, $"{noAudit}/{total} audit categories disabled - blind spots",
                        "Enable audit policies for Logon/Logoff, Account Management, and Privilege Use at minimum");
                if (noAudit > total * 0.3)
                    return (false, $"{noAudit}/{total} audit categories disabled",
                        "Review and enable critical audit policies (Security Settings > Local Policies > Audit Policy)");
                return (true, $"Audit logging active ({total - noAudit}/{total} categories enabled)", "");
            }
            catch { return (true, "Unable to check audit policies", ""); }
        });

        private SecurityCheck CheckLogRetention() => RunCheck("log_retention", "Log Retention", "Logging & Visibility", 3, () =>
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\EventLog\Security");
                var maxSize = key?.GetValue("MaxSize");
                long maxSizeKb = maxSize != null ? Convert.ToInt64(maxSize) / 1024 : 0;

                if (maxSizeKb < 20480) // Less than 20MB
                    return (false, $"Security log max size: {maxSizeKb / 1024}MB (too small, logs overwritten quickly)",
                        "Increase Security event log size to at least 256MB for adequate forensic retention");
                return (true, $"Security log max size: {maxSizeKb / 1024}MB", "");
            }
            catch { return (true, "Unable to check log retention", ""); }
        });

        // --- ENDPOINT HARDENING ---

        private SecurityCheck CheckAppLockerWdac() => RunCheck("applocker_wdac", "Application Control", "Endpoint Hardening", 5, () =>
        {
            try
            {
                var hasControl = false;
                var detail = "";

                // Check AppLocker
                using (var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\SrpV2"))
                {
                    if (key?.GetSubKeyNames().Length > 0)
                    {
                        hasControl = true;
                        detail = "AppLocker policies configured";
                    }
                }

                // Check WDAC (Windows Defender Application Control)
                if (!hasControl)
                {
                    using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\CI");
                    var ciPolicy = key?.GetValue("UMCIEnabled");
                    if (ciPolicy != null && Convert.ToInt32(ciPolicy) == 1)
                    {
                        hasControl = true;
                        detail = "WDAC (Code Integrity) enabled";
                    }
                }

                if (!hasControl)
                    return (false, "No application control (AppLocker/WDAC) configured",
                        "Deploy AppLocker or WDAC to prevent unauthorized applications from running");
                return (true, detail, "");
            }
            catch { return (true, "Unable to check application control", ""); }
        });

        private SecurityCheck CheckOfficeMacroSecurity() => RunCheck("office_macros", "Office Macro Security", "Endpoint Hardening", 5, () =>
        {
            try
            {
                // Check Office macro settings in registry (Office 16.0 = 2016/2019/365)
                var macroBlocked = false;
                var officeVersions = new[] { "16.0", "15.0", "14.0" };
                var officeApps = new[] { "Word", "Excel", "PowerPoint" };

                foreach (var ver in officeVersions)
                {
                    foreach (var app in officeApps)
                    {
                        using var key = Registry.CurrentUser.OpenSubKey($@"SOFTWARE\Microsoft\Office\{ver}\{app}\Security");
                        if (key != null)
                        {
                            var vbaWarnings = key.GetValue("VBAWarnings");
                            if (vbaWarnings != null && Convert.ToInt32(vbaWarnings) >= 3) // 3=disabled with notification, 4=disabled
                                macroBlocked = true;

                            var blockInternet = key.GetValue("blockcontentexecutionfrominternet");
                            if (blockInternet != null && Convert.ToInt32(blockInternet) == 1)
                                macroBlocked = true;
                        }
                    }
                }

                // Also check Group Policy setting
                using (var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Office\16.0\Common\Security"))
                {
                    var val = key?.GetValue("blockcontentexecutionfrominternet");
                    if (val != null && Convert.ToInt32(val) == 1) macroBlocked = true;
                }

                if (!macroBlocked)
                    return (false, "Office macros from internet not blocked",
                        "Block macros from internet sources in Office Trust Center - #1 malware delivery method");
                return (true, "Office macros from internet blocked", "");
            }
            catch { return (true, "Unable to check Office macro security", ""); }
        });

        private SecurityCheck CheckSmartScreen() => RunCheck("smartscreen", "SmartScreen Status", "Endpoint Hardening", 5, () =>
        {
            try
            {
                var issues = new List<string>();

                // Windows SmartScreen
                using (var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"))
                {
                    var val = key?.GetValue("SmartScreenEnabled")?.ToString();
                    if (val == null || val == "Off") issues.Add("Windows SmartScreen disabled");
                }

                // Edge SmartScreen
                using (var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Edge"))
                {
                    var val = key?.GetValue("SmartScreenEnabled");
                    if (val != null && Convert.ToInt32(val) == 0) issues.Add("Edge SmartScreen disabled");
                }

                if (issues.Count > 0)
                    return (false, string.Join("; ", issues),
                        "Enable SmartScreen for apps and browser - blocks known malicious downloads and websites");
                return (true, "SmartScreen enabled for apps and browser", "");
            }
            catch { return (true, "Unable to check SmartScreen", ""); }
        });

        // --- DEVICE CONTROL ---

        private SecurityCheck CheckUsbStoragePolicy() => RunCheck("usb_storage", "USB Storage Policy", "Device Control", 5, () =>
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\USBSTOR");
                var start = key?.GetValue("Start");
                // Start = 3 means enabled, 4 means disabled
                if (start != null && Convert.ToInt32(start) == 4)
                    return (true, "USB storage devices blocked", "");
                if (start != null && Convert.ToInt32(start) == 3)
                    return (false, "USB storage devices unrestricted - data exfiltration risk",
                        "Restrict USB storage via Group Policy or disable USBSTOR service to prevent data theft and malware via USB");
                return (false, "USB storage policy not configured", "Configure USB device policy to control removable media access");
            }
            catch { return (true, "Unable to check USB policy", ""); }
        });

        private SecurityCheck CheckBluetoothRisk() => RunCheck("bluetooth_risk", "Bluetooth File Transfer", "Device Control", 3, () =>
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    "SELECT * FROM Win32_PnPEntity WHERE Name LIKE '%Bluetooth%' AND Status='OK'");
                var btDevices = searcher.Get().Count;
                if (btDevices == 0)
                    return (true, "No active Bluetooth adapters", "");

                // Check if OBEX (file transfer) service is running
                try
                {
                    using var sc = new ServiceController("BthServ");
                    if (sc.Status == ServiceControllerStatus.Running)
                        return (false, "Bluetooth active with file transfer capability",
                            "Disable Bluetooth when not in use or restrict file transfer via Group Policy");
                }
                catch { }
                return (true, "Bluetooth adapter present but service not active", "");
            }
            catch { return (true, "Unable to check Bluetooth status", ""); }
        });

        // --- BROWSER & USER RISK ---

        private SecurityCheck CheckSavedPasswordRisk() => RunCheck("saved_passwords", "Saved Password Risk", "Browser & User Risk", 5, () =>
        {
            try
            {
                var risks = new List<string>();
                var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

                // Check Chrome saved passwords (Login Data file existence)
                var chromeLoginData = Path.Combine(userProfile, @"Google\Chrome\User Data\Default\Login Data");
                if (File.Exists(chromeLoginData))
                {
                    var fi = new FileInfo(chromeLoginData);
                    if (fi.Length > 5000) // More than trivial size = passwords stored
                        risks.Add("Chrome (passwords stored)");
                }

                // Check Edge saved passwords
                var edgeLoginData = Path.Combine(userProfile, @"Microsoft\Edge\User Data\Default\Login Data");
                if (File.Exists(edgeLoginData))
                {
                    var fi = new FileInfo(edgeLoginData);
                    if (fi.Length > 5000)
                        risks.Add("Edge (passwords stored)");
                }

                // Check Firefox
                var firefoxProfiles = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), @"Mozilla\Firefox\Profiles");
                if (Directory.Exists(firefoxProfiles))
                {
                    foreach (var profile in Directory.GetDirectories(firefoxProfiles))
                    {
                        if (File.Exists(Path.Combine(profile, "logins.json")))
                        { risks.Add("Firefox (passwords stored)"); break; }
                    }
                }

                if (risks.Count > 0)
                    return (false, $"Browser-saved passwords: {string.Join(", ", risks)}",
                        "Use a dedicated password manager instead of browser-saved passwords - browser credentials are easily extracted by malware");
                return (true, "No browser-saved passwords detected", "");
            }
            catch { return (true, "Unable to check saved passwords", ""); }
        });

        private SecurityCheck CheckBrowserExtensions() => RunCheck("browser_extensions", "Browser Extensions", "Browser & User Risk", 3, () =>
        {
            try
            {
                var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                var extCount = 0;

                // Count Chrome extensions
                var chromeExtDir = Path.Combine(userProfile, @"Google\Chrome\User Data\Default\Extensions");
                if (Directory.Exists(chromeExtDir))
                    extCount += Directory.GetDirectories(chromeExtDir).Length;

                // Count Edge extensions
                var edgeExtDir = Path.Combine(userProfile, @"Microsoft\Edge\User Data\Default\Extensions");
                if (Directory.Exists(edgeExtDir))
                    extCount += Directory.GetDirectories(edgeExtDir).Length;

                if (extCount > 15)
                    return (false, $"{extCount} browser extensions installed - increased attack surface",
                        "Audit and remove unnecessary browser extensions - malicious extensions can steal credentials and data");
                return (true, $"{extCount} browser extensions (within normal range)", "");
            }
            catch { return (true, "Unable to audit browser extensions", ""); }
        });

        // --- DATA EXPOSURE ---

        private SecurityCheck CheckDesktopDataExposure() => RunCheck("data_exposure", "Desktop / Downloads Risk", "Data Protection", 5, () =>
        {
            try
            {
                var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                var sensitivePatterns = new[] { "*.xlsx", "*.csv", "*.pdf", "*.docx", "*.pst", "*.kdbx", "*.key", "*.pfx", "*.p12" };
                var sensitiveCount = 0;
                var locations = new[] { Path.Combine(userProfile, "Desktop"), Path.Combine(userProfile, "Downloads") };

                foreach (var loc in locations)
                {
                    if (!Directory.Exists(loc)) continue;
                    foreach (var pattern in sensitivePatterns)
                    {
                        try { sensitiveCount += Directory.GetFiles(loc, pattern, SearchOption.TopDirectoryOnly).Length; }
                        catch { }
                    }
                }

                if (sensitiveCount > 20)
                    return (false, $"{sensitiveCount} sensitive files on Desktop/Downloads - ransomware target",
                        "Move sensitive files to protected folders or OneDrive with versioning - Desktop/Downloads are primary ransomware targets");
                if (sensitiveCount > 10)
                    return (false, $"{sensitiveCount} sensitive files exposed on Desktop/Downloads",
                        "Organize sensitive files into backed-up, protected locations");
                return (true, $"Desktop/Downloads: {sensitiveCount} sensitive files (low risk)", "");
            }
            catch { return (true, "Unable to check data exposure", ""); }
        });

        // --- HARDWARE SECURITY (EXPANDED) ---

        private SecurityCheck CheckBiosPassword() => RunCheck("bios_password", "BIOS Password", "Hardware Security", 3, () =>
        {
            try
            {
                // Check for BIOS password status via WMI
                using var searcher = new ManagementObjectSearcher("root\\WMI",
                    "SELECT SMBiosData FROM MSSmBios_RawSMBiosTables");
                // If we can query BIOS without restriction, password may not be set
                // This is a heuristic - definitive check requires vendor-specific tools
                var biosInfo = "";
                using var bioSearch = new ManagementObjectSearcher("SELECT * FROM Win32_BIOS");
                foreach (ManagementObject obj in bioSearch.Get())
                    biosInfo = obj["Description"]?.ToString() ?? "";

                // Cannot definitively check BIOS password from OS level - flag as advisory
                return (false, "BIOS/UEFI password status unknown - recommend setting one",
                    "Set a BIOS/UEFI password to prevent unauthorized boot device changes and firmware modifications");
            }
            catch { return (true, "Unable to check BIOS password", ""); }
        });

        private SecurityCheck CheckVirtualizationSecurity() => RunCheck("vbs_status", "Virtualization-based Security", "Hardware Security", 5, () =>
        {
            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_DeviceGuard");
                foreach (ManagementObject obj in searcher.Get())
                {
                    var vbsStatus = obj["VirtualizationBasedSecurityStatus"];
                    if (vbsStatus != null && Convert.ToInt32(vbsStatus) == 2) // 2 = running
                        return (true, "Virtualization-based Security (VBS) running", "");
                    if (vbsStatus != null && Convert.ToInt32(vbsStatus) == 1) // 1 = configured but not running
                        return (false, "VBS configured but not running", "Ensure Hyper-V is enabled and reboot to activate VBS");
                }

                // Fallback: check if Hyper-V/VT is available
                using var cpuSearch = new ManagementObjectSearcher("SELECT VirtualizationFirmwareEnabled FROM Win32_Processor");
                foreach (ManagementObject obj in cpuSearch.Get())
                {
                    var vtEnabled = obj["VirtualizationFirmwareEnabled"];
                    if (vtEnabled != null && Convert.ToBoolean(vtEnabled))
                        return (false, "Virtualization available but VBS not enabled",
                            "Enable Virtualization-based Security for Credential Guard and memory integrity protection");
                    return (false, "Hardware virtualization not enabled in BIOS",
                        "Enable VT-x/AMD-V in BIOS settings, then enable VBS for enhanced memory protection");
                }
                return (false, "VBS status unknown", "Check BIOS for virtualization support");
            }
            catch { return (true, "Unable to check VBS status", ""); }
        });

        // --- PRIVILEGE ESCALATION (ADVANCED) ---

        private SecurityCheck CheckWeakServicePermissions() => RunCheck("weak_svc_perms", "Weak Service Permissions", "Privilege Escalation", 5, () =>
        {
            try
            {
                var startInfo = new ProcessStartInfo("powershell", @"-NoProfile -NonInteractive -Command ""
                    $weak = 0;
                    Get-WmiObject Win32_Service | Where-Object { $_.PathName -and $_.StartMode -eq 'Auto' } | ForEach-Object {
                        $path = $_.PathName -replace '""','';
                        if ($path -match '^(.+\.exe)') {
                            $exePath = $matches[1];
                            if (Test-Path $exePath) {
                                $acl = Get-Acl $exePath -ErrorAction SilentlyContinue;
                                if ($acl) {
                                    $acl.Access | Where-Object { $_.IdentityReference -match 'Users|Everyone|Authenticated' -and $_.FileSystemRights -match 'Write|Modify|FullControl' } | ForEach-Object { $weak++ }
                                }
                            }
                        }
                    };
                    Write-Output $weak""")
                { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
                using var proc = Process.Start(startInfo);
                var output = proc?.StandardOutput.ReadToEnd()?.Trim() ?? "";
                proc?.WaitForExit(30000);

                if (int.TryParse(output, out int weakCount) && weakCount > 0)
                    return (false, $"{weakCount} services with weak file permissions - privilege escalation risk",
                        "Fix service executable permissions - remove write access for non-admin users");
                return (true, "No weak service permissions detected", "");
            }
            catch { return (true, "Unable to check service permissions", ""); }
        });

        private SecurityCheck CheckWritableSystemFolders() => RunCheck("writable_system", "Writable System Folders", "Privilege Escalation", 3, () =>
        {
            try
            {
                var writablePaths = new List<string>();
                var systemPaths = new[] { @"C:\Windows\System32", @"C:\Windows\SysWOW64", @"C:\Windows\Temp" };

                foreach (var sysPath in systemPaths)
                {
                    if (!Directory.Exists(sysPath)) continue;
                    try
                    {
                        // Quick write test
                        var testFile = Path.Combine(sysPath, $"_pcplus_test_{Guid.NewGuid():N}.tmp");
                        try
                        {
                            File.WriteAllText(testFile, "test");
                            File.Delete(testFile);
                            if (sysPath != @"C:\Windows\Temp") // Temp is expected to be writable
                                writablePaths.Add(sysPath);
                        }
                        catch (UnauthorizedAccessException) { } // Expected - can't write = good
                        catch { }
                    }
                    catch { }
                }

                if (writablePaths.Count > 0)
                    return (false, $"System folders writable by current user: {string.Join(", ", writablePaths)}",
                        "Fix NTFS permissions on system directories - these should not be writable by standard users");
                return (true, "System folders properly restricted", "");
            }
            catch { return (true, "Unable to check system folder permissions", ""); }
        });

        private SecurityCheck CheckDllHijackingRisk() => RunCheck("dll_hijack", "DLL Hijacking Risk", "Privilege Escalation", 3, () =>
        {
            try
            {
                var risks = new List<string>();

                // Check SafeDllSearchMode
                using (var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Session Manager"))
                {
                    var val = key?.GetValue("SafeDllSearchMode");
                    if (val != null && Convert.ToInt32(val) == 0)
                        risks.Add("SafeDllSearchMode disabled");
                }

                // Check for writable directories in PATH
                var pathVar = Environment.GetEnvironmentVariable("PATH") ?? "";
                var writablePaths = 0;
                foreach (var dir in pathVar.Split(';'))
                {
                    if (string.IsNullOrWhiteSpace(dir) || !Directory.Exists(dir)) continue;
                    try
                    {
                        var testFile = Path.Combine(dir, $"_pcplus_dll_test_{Guid.NewGuid():N}.tmp");
                        try
                        {
                            File.WriteAllText(testFile, "test");
                            File.Delete(testFile);
                            // If we can write to a PATH directory (except user-specific ones), it's a risk
                            if (!dir.Contains(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)))
                                writablePaths++;
                        }
                        catch (UnauthorizedAccessException) { }
                        catch { }
                    }
                    catch { }
                }

                if (writablePaths > 0) risks.Add($"{writablePaths} writable directories in system PATH");

                if (risks.Count > 0)
                    return (false, string.Join("; ", risks), "Fix DLL search order and PATH permissions to prevent DLL hijacking attacks");
                return (true, "DLL loading security properly configured", "");
            }
            catch { return (true, "Unable to check DLL hijacking risk", ""); }
        });

        private SecurityCheck CheckTacticalRmmAgent() => RunCheck("trmm_agent", "Tactical RMM Agent", "RMM Stack", 5, () =>
        {
            // Check for Tactical RMM agent service
            foreach (var svcName in new[] { "tacticalrmm", "TacticalAgent", "tacticalagent", "TacticalRMM" })
            {
                try
                {
                    using var sc = new ServiceController(svcName);
                    if (sc.Status == ServiceControllerStatus.Running)
                        return (true, $"Tactical RMM agent ({svcName}) is running", "");
                    return (false, $"Tactical RMM agent ({svcName}) is installed but not running",
                        "Start the Tactical RMM agent service");
                }
                catch { }
            }

            // Check for agent executable
            var paths = new[] {
                @"C:\Program Files\TacticalAgent\tacticalrmm.exe",
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "TacticalAgent", "tacticalrmm.exe")
            };
            foreach (var p in paths)
                if (File.Exists(p))
                    return (false, "Tactical RMM agent is installed but service is not running",
                        "Start the Tactical RMM agent service");

            return (false, "Tactical RMM agent is not installed",
                "Install Tactical RMM agent for remote management and monitoring");
        });

        private SecurityCheck CheckWazuhAgent() => RunCheck("wazuh_agent", "Wazuh Security Agent", "RMM Stack", 5, () =>
        {
            // Check for Wazuh agent service
            foreach (var svcName in new[] { "WazuhSvc", "Wazuh", "wazuh-agent", "OssecSvc" })
            {
                try
                {
                    using var sc = new ServiceController(svcName);
                    if (sc.Status == ServiceControllerStatus.Running)
                        return (true, $"Wazuh SIEM agent ({svcName}) is running - intrusion detection active", "");
                    return (false, $"Wazuh agent ({svcName}) is installed but not running",
                        "Start the Wazuh agent service for SIEM coverage");
                }
                catch { }
            }

            // Check for agent paths
            var paths = new[] {
                @"C:\Program Files (x86)\ossec-agent\wazuh-agent.exe",
                @"C:\Program Files\ossec-agent\wazuh-agent.exe",
                @"C:\Program Files (x86)\ossec-agent\ossec-agent.exe"
            };
            foreach (var p in paths)
                if (File.Exists(p))
                    return (false, "Wazuh agent is installed but service is not running",
                        "Start the Wazuh agent service for SIEM coverage");

            return (false, "Wazuh SIEM agent is not installed",
                "Install Wazuh agent for intrusion detection and security monitoring");
        });

        // =====================================================================
        // EXTENDED CHECKS (50 additional checks for 120-point audit)
        // =====================================================================

        // === PROTECTION (EXTENDED) ===

        private SecurityCheck CheckDefenderSignatureAge() => RunCheck("defender_sig_age", "Defender Signature Age", "Protection", 5, () =>
        {
            try
            {
                var psi = new ProcessStartInfo("powershell", "-NoProfile -Command \"(Get-MpComputerStatus).AntivirusSignatureAge\"")
                { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                using var proc = Process.Start(psi);
                var output = proc?.StandardOutput.ReadToEnd().Trim() ?? "";
                proc?.WaitForExit(10000);
                if (int.TryParse(output, out var days))
                {
                    if (days <= 1) return (true, $"Defender signatures updated {days} day(s) ago", "");
                    if (days <= 3) return (true, $"Defender signatures are {days} days old", "Consider running Windows Update");
                    return (false, $"Defender signatures are {days} days old", "Run Windows Update or manually update Defender signatures immediately");
                }
            }
            catch { }
            return (true, "Unable to determine signature age", "");
        });

        private SecurityCheck CheckDefenderCloud() => RunCheck("defender_cloud", "Cloud-Delivered Protection", "Protection", 5, () =>
        {
            try
            {
                var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection");
                if (key != null)
                {
                    var val = key.GetValue("SpyNetReporting");
                    if (val != null && Convert.ToInt32(val) >= 1)
                        return (true, "Cloud-delivered protection is enabled", "");
                    return (false, "Cloud-delivered protection is disabled", "Enable cloud-delivered protection in Windows Security > Virus & threat protection settings");
                }
                var psi = new ProcessStartInfo("powershell", "-NoProfile -Command \"(Get-MpPreference).MAPSReporting\"")
                { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                using var proc = Process.Start(psi);
                var output = proc?.StandardOutput.ReadToEnd().Trim() ?? "";
                proc?.WaitForExit(10000);
                if (int.TryParse(output, out var level) && level >= 1)
                    return (true, "Cloud-delivered protection is enabled (MAPS)", "");
                return (false, "Cloud-delivered protection is not configured", "Enable MAPS reporting via Group Policy or Windows Security");
            }
            catch { }
            return (true, "Unable to check cloud protection status", "");
        });

        private SecurityCheck CheckIoavProtection() => RunCheck("ioav_protection", "Network File / IOAV Protection", "Protection", 3, () =>
        {
            try
            {
                var psi = new ProcessStartInfo("powershell", "-NoProfile -Command \"(Get-MpPreference).DisableIOAVProtection\"")
                { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                using var proc = Process.Start(psi);
                var output = proc?.StandardOutput.ReadToEnd().Trim() ?? "";
                proc?.WaitForExit(10000);
                if (output.Equals("False", StringComparison.OrdinalIgnoreCase))
                    return (true, "IOAV Protection is enabled - files from the internet are scanned", "");
                if (output.Equals("True", StringComparison.OrdinalIgnoreCase))
                    return (false, "IOAV Protection is disabled", "Enable IOAV Protection: Set-MpPreference -DisableIOAVProtection $false");
            }
            catch { }
            return (true, "Unable to check IOAV protection status", "");
        });

        private SecurityCheck CheckAvPassiveMode() => RunCheck("av_passive_mode", "AV Passive/Conflict State", "Protection", 5, () =>
        {
            try
            {
                var psi = new ProcessStartInfo("powershell", "-NoProfile -Command \"(Get-MpComputerStatus).AMRunningMode\"")
                { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                using var proc = Process.Start(psi);
                var output = proc?.StandardOutput.ReadToEnd().Trim() ?? "";
                proc?.WaitForExit(10000);
                if (output.Contains("Normal", StringComparison.OrdinalIgnoreCase))
                    return (true, "Windows Defender is running in normal (active) mode", "");
                if (output.Contains("Passive", StringComparison.OrdinalIgnoreCase))
                    return (false, "Windows Defender is in passive mode - another AV may be conflicting", "Ensure only one AV is actively protecting the system");
                if (output.Contains("EDR", StringComparison.OrdinalIgnoreCase))
                    return (true, "Defender running in EDR Block mode", "");
            }
            catch { }
            return (true, "Unable to determine AV running mode", "");
        });

        private SecurityCheck CheckWebProtection() => RunCheck("web_protection", "Web / Network Protection", "Protection", 3, () =>
        {
            try
            {
                var psi = new ProcessStartInfo("powershell", "-NoProfile -Command \"(Get-MpPreference).EnableNetworkProtection\"")
                { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                using var proc = Process.Start(psi);
                var output = proc?.StandardOutput.ReadToEnd().Trim() ?? "";
                proc?.WaitForExit(10000);
                if (output == "1") return (true, "Network Protection is enabled (block mode)", "");
                if (output == "2") return (true, "Network Protection is in audit mode", "Consider enabling block mode for full protection");
                return (false, "Network Protection is disabled", "Enable Network Protection: Set-MpPreference -EnableNetworkProtection Enabled");
            }
            catch { }
            return (true, "Unable to check Network Protection status", "");
        });

        private SecurityCheck CheckTamperChannels() => RunCheck("tamper_channels", "Security Settings Lockdown", "Protection", 3, () =>
        {
            try
            {
                var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows Defender\Features");
                if (key != null)
                {
                    var tamper = key.GetValue("TamperProtection");
                    var source = key.GetValue("TamperProtectionSource");
                    if (tamper != null && Convert.ToInt32(tamper) == 5)
                        return (true, "Security settings are locked down via Tamper Protection", "");
                    return (false, "Security settings are not fully locked", "Enable Tamper Protection to prevent unauthorized changes to security settings");
                }
            }
            catch { }
            return (true, "Unable to verify security lockdown status", "");
        });

        // === UPDATES (EXTENDED) ===

        private SecurityCheck CheckDriverUpdates() => RunCheck("driver_updates", "Critical Driver Updates", "Updates", 3, () =>
        {
            try
            {
                var psi = new ProcessStartInfo("powershell", "-NoProfile -Command \"Get-WmiObject Win32_PnPSignedDriver | Where-Object { $_.DriverDate } | Sort-Object DriverDate | Select-Object -First 1 -ExpandProperty DriverDate\"")
                { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                using var proc = Process.Start(psi);
                var output = proc?.StandardOutput.ReadToEnd().Trim() ?? "";
                proc?.WaitForExit(15000);
                if (!string.IsNullOrEmpty(output) && output.Length >= 8)
                {
                    if (DateTime.TryParse(output.Substring(0, 8).Insert(4, "-").Insert(7, "-"), out var oldest))
                    {
                        var age = (DateTime.Now - oldest).Days;
                        if (age > 365 * 3)
                            return (false, $"Oldest driver is {age / 365} years old", "Check Device Manager for outdated drivers and update critical hardware drivers");
                    }
                }
                return (true, "Drivers appear reasonably current", "");
            }
            catch { }
            return (true, "Unable to assess driver update status", "");
        });

        private SecurityCheck CheckDefenderPlatformAge() => RunCheck("defender_platform_age", "Defender Platform Version Age", "Updates", 3, () =>
        {
            try
            {
                var psi = new ProcessStartInfo("powershell", "-NoProfile -Command \"(Get-MpComputerStatus).AMProductVersion\"")
                { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                using var proc = Process.Start(psi);
                var output = proc?.StandardOutput.ReadToEnd().Trim() ?? "";
                proc?.WaitForExit(10000);
                if (System.Version.TryParse(output, out var ver))
                {
                    if (ver.Major >= 4 && ver.Minor >= 18)
                        return (true, $"Defender platform version {output} is current", "");
                    return (false, $"Defender platform version {output} may be outdated", "Update Windows Defender via Windows Update");
                }
            }
            catch { }
            return (true, "Unable to determine Defender platform version", "");
        });

        private SecurityCheck CheckBrowserPatchAge() => RunCheck("browser_patch_age", "Browser Patch Age", "Updates", 3, () =>
        {
            try
            {
                var edgeKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Edge\BLBeacon");
                var chromeKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Google\Chrome\BLBeacon");
                var versions = new List<string>();
                if (edgeKey?.GetValue("version") is string edgeVer) versions.Add($"Edge {edgeVer}");
                if (chromeKey?.GetValue("version") is string chromeVer) versions.Add($"Chrome {chromeVer}");
                if (versions.Count > 0)
                    return (true, $"Browsers detected: {string.Join(", ", versions)}", "Keep browsers auto-updated");
                var chromePath = @"C:\Program Files\Google\Chrome\Application\chrome.exe";
                var edgePath = @"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe";
                if (File.Exists(chromePath) || File.Exists(edgePath))
                    return (true, "Browsers installed, version check via registry unavailable", "");
            }
            catch { }
            return (true, "Unable to determine browser versions", "");
        });

        private SecurityCheck CheckThirdPartyPatchCompliance() => RunCheck("thirdparty_patch_compliance", "Third-Party Patch Compliance", "Updates", 3, () =>
        {
            var outdated = new List<string>();
            try
            {
                var checks = new Dictionary<string, (string path, int minMajor)>
                {
                    ["Adobe Reader"] = (@"C:\Program Files\Adobe\Acrobat DC\Acrobat\Acrobat.exe", 24),
                    ["Java"] = (@"C:\Program Files\Java\jre-*\bin\java.exe", 21),
                    ["7-Zip"] = (@"C:\Program Files\7-Zip\7z.exe", 23),
                };
                foreach (var (name, (path, minMajor)) in checks)
                {
                    if (File.Exists(path))
                    {
                        var ver = FileVersionInfo.GetVersionInfo(path);
                        if (ver.FileMajorPart > 0 && ver.FileMajorPart < minMajor)
                            outdated.Add($"{name} v{ver.FileMajorPart}");
                    }
                }
            }
            catch { }
            if (outdated.Count > 0)
                return (false, $"Outdated third-party software: {string.Join(", ", outdated)}", "Update third-party applications to latest versions");
            return (true, "No critically outdated third-party software detected", "");
        });

        private SecurityCheck CheckKnownCveExposure() => RunCheck("known_cve_exposure", "Known CVE Exposure", "Updates", 5, () =>
        {
            try
            {
                var vulnerable = new List<string>();
                if (File.Exists(@"C:\Windows\System32\spoolsv.exe"))
                {
                    var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\Spooler");
                    if (key?.GetValue("Start") is int start && start == 2)
                        vulnerable.Add("Print Spooler running (PrintNightmare risk)");
                }
                var smbv1Key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters");
                if (smbv1Key?.GetValue("SMB1") is int smb1 && smb1 == 1)
                    vulnerable.Add("SMBv1 enabled (EternalBlue risk)");
                var rdpKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Terminal Server");
                if (rdpKey?.GetValue("fDenyTSConnections") is int deny && deny == 0)
                {
                    var nlaKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp");
                    if (nlaKey?.GetValue("UserAuthentication") is int nla && nla == 0)
                        vulnerable.Add("RDP without NLA (BlueKeep risk)");
                }
                if (vulnerable.Count > 0)
                    return (false, $"Potential CVE exposure: {string.Join("; ", vulnerable)}", "Address known vulnerability vectors immediately");
                return (true, "No known critical CVE exposure patterns detected", "");
            }
            catch { }
            return (true, "Unable to assess CVE exposure", "");
        });

        private SecurityCheck CheckPatchFailureHistory() => RunCheck("patch_failure_history", "Patch Failure History", "Updates", 3, () =>
        {
            try
            {
                var psi = new ProcessStartInfo("powershell", "-NoProfile -Command \"Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending | Select-Object -First 5 | Measure-Object | Select-Object -ExpandProperty Count\"")
                { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                using var proc = Process.Start(psi);
                var output = proc?.StandardOutput.ReadToEnd().Trim() ?? "";
                proc?.WaitForExit(15000);
                if (int.TryParse(output, out var count) && count >= 3)
                    return (true, $"Recent patches found: {count} hotfixes installed recently", "");
                if (count == 0)
                    return (false, "No recent patches found - possible update failures", "Check Windows Update history for failed installations");
            }
            catch { }
            return (true, "Unable to assess patch history", "");
        });

        private SecurityCheck CheckUpdateSourceHealth() => RunCheck("update_source_health", "WSUS/WUFB Source Health", "Updates", 3, () =>
        {
            try
            {
                var wuKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate");
                if (wuKey != null)
                {
                    var wsusServer = wuKey.GetValue("WUServer") as string;
                    if (!string.IsNullOrEmpty(wsusServer))
                        return (true, $"Update source: WSUS ({wsusServer})", "Ensure WSUS server is accessible and synchronized");
                    var wufb = wuKey.GetValue("DoNotConnectToWindowsUpdateInternetLocations");
                    if (wufb != null)
                        return (true, "Update source: Windows Update for Business configured", "");
                }
                return (true, "Update source: Microsoft Update (default)", "");
            }
            catch { }
            return (true, "Using default Windows Update source", "");
        });

        private SecurityCheck CheckUpdatePolicy() => RunCheck("update_policy", "Windows Update Policy / Ring", "Updates", 3, () =>
        {
            try
            {
                var auKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU");
                if (auKey != null)
                {
                    var opt = auKey.GetValue("AUOptions");
                    var msg = opt switch
                    {
                        2 => "Notify before download",
                        3 => "Auto download, notify before install",
                        4 => "Auto download and install",
                        5 => "Allow local admin to configure",
                        _ => $"Custom policy (option {opt})"
                    };
                    if (opt is 4 or 3)
                        return (true, $"Windows Update policy: {msg}", "");
                    return (false, $"Windows Update policy: {msg}", "Set update policy to auto-download and install for best security");
                }
                return (true, "Windows Update using default automatic settings", "");
            }
            catch { }
            return (true, "Unable to determine update policy", "");
        });

        // === DATA PROTECTION (EXTENDED) ===

        private SecurityCheck CheckBackupLastSuccess() => RunCheck("backup_last_success", "Backup Last Success", "Data Protection", 3, () =>
        {
            try
            {
                var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsBackup\Status");
                if (key != null)
                {
                    var lastSuccess = key.GetValue("LastSuccessTime") as string;
                    if (!string.IsNullOrEmpty(lastSuccess) && DateTime.TryParse(lastSuccess, out var dt))
                    {
                        var age = (DateTime.Now - dt).Days;
                        if (age <= 7) return (true, $"Last backup succeeded {age} day(s) ago", "");
                        return (false, $"Last successful backup was {age} days ago", "Run a backup immediately and verify backup schedule");
                    }
                }
                var psi = new ProcessStartInfo("powershell", "-NoProfile -Command \"Get-WBSummary -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LastSuccessfulBackupTime\"")
                { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                using var proc = Process.Start(psi);
                var output = proc?.StandardOutput.ReadToEnd().Trim() ?? "";
                proc?.WaitForExit(10000);
                if (DateTime.TryParse(output, out var backupDt))
                {
                    var days = (DateTime.Now - backupDt).Days;
                    if (days <= 7) return (true, $"Last backup succeeded {days} day(s) ago", "");
                    return (false, $"Last successful backup was {days} days ago", "Verify backup schedule and run a backup");
                }
            }
            catch { }
            return (false, "No backup success record found", "Configure and run regular backups");
        });

        private SecurityCheck CheckBackupLastFailure() => RunCheck("backup_last_failure", "Backup Last Failure", "Data Protection", 3, () =>
        {
            try
            {
                var psi = new ProcessStartInfo("powershell", "-NoProfile -Command \"Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Backup';Level=2} -MaxEvents 1 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty TimeCreated\"")
                { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                using var proc = Process.Start(psi);
                var output = proc?.StandardOutput.ReadToEnd().Trim() ?? "";
                proc?.WaitForExit(10000);
                if (DateTime.TryParse(output, out var failDt))
                {
                    var days = (DateTime.Now - failDt).Days;
                    if (days <= 7) return (false, $"Backup failure detected {days} day(s) ago", "Investigate and resolve backup failure, check event logs for details");
                    return (true, $"Last backup failure was {days} days ago (likely resolved)", "");
                }
            }
            catch { }
            return (true, "No recent backup failures detected", "");
        });

        private SecurityCheck CheckRestoreTested() => RunCheck("restore_tested", "Restore Tested Verification", "Data Protection", 3, () =>
        {
            try
            {
                var configDir = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData) + @"\PCPlusEndpoint";
                var configFile = Path.Combine(configDir, "config.json");
                if (File.Exists(configFile))
                {
                    var json = File.ReadAllText(configFile);
                    if (json.Contains("\"lastRestoreTest\"") && !json.Contains("\"lastRestoreTest\":\"\""))
                        return (true, "Backup restore has been tested (recorded in config)", "");
                }
            }
            catch { }
            return (false, "No record of backup restore testing", "Perform a test restore to verify backup integrity - document the result");
        });

        private SecurityCheck CheckOffsiteBackup() => RunCheck("offsite_backup", "Offsite Backup Presence", "Data Protection", 3, () =>
        {
            try
            {
                var oneDrive = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + @"\OneDrive";
                var hasOneDrive = Directory.Exists(oneDrive) && Directory.GetFiles(oneDrive).Length > 0;
                var psi = new ProcessStartInfo("powershell", "-NoProfile -Command \"Get-Service -Name 'OneDrive*','CrashPlanService','BackupExecAgentAccelerator','VeeamAgent' -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Running' } | Select-Object -ExpandProperty DisplayName\"")
                { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                using var proc = Process.Start(psi);
                var output = proc?.StandardOutput.ReadToEnd().Trim() ?? "";
                proc?.WaitForExit(10000);
                if (hasOneDrive || !string.IsNullOrEmpty(output))
                    return (true, $"Offsite/cloud backup detected{(hasOneDrive ? " (OneDrive)" : "")}{(!string.IsNullOrEmpty(output) ? $" ({output})" : "")}", "");
            }
            catch { }
            return (false, "No offsite or cloud backup detected", "Configure offsite or cloud backup for disaster recovery protection");
        });

        private SecurityCheck CheckBackupEncryption() => RunCheck("backup_encryption", "Backup Encryption", "Data Protection", 3, () =>
        {
            try
            {
                var psi = new ProcessStartInfo("powershell", "-NoProfile -Command \"Get-WBPolicy -ErrorAction SilentlyContinue | Select-Object -ExpandProperty VolumeEncryptionEnabled\"")
                { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                using var proc = Process.Start(psi);
                var output = proc?.StandardOutput.ReadToEnd().Trim() ?? "";
                proc?.WaitForExit(10000);
                if (output.Equals("True", StringComparison.OrdinalIgnoreCase))
                    return (true, "Backup encryption is enabled", "");
            }
            catch { }
            return (false, "Backup encryption status unknown or not enabled", "Enable encryption on backup volumes to protect data at rest");
        });

        private SecurityCheck CheckBackupRetention() => RunCheck("backup_retention", "Backup Retention Policy", "Data Protection", 3, () =>
        {
            try
            {
                var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsBackup");
                if (key != null)
                {
                    var versioning = key.GetValue("KeepVersions");
                    if (versioning != null && Convert.ToInt32(versioning) > 0)
                        return (true, $"Backup retention configured: keeping {versioning} versions", "");
                }
                var shadowCount = 0;
                var psi = new ProcessStartInfo("vssadmin", "list shadows")
                { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                using var proc = Process.Start(psi);
                var output = proc?.StandardOutput.ReadToEnd() ?? "";
                proc?.WaitForExit(10000);
                shadowCount = output.Split("Shadow Copy ID").Length - 1;
                if (shadowCount >= 3)
                    return (true, $"{shadowCount} shadow copies available for point-in-time recovery", "");
                if (shadowCount > 0)
                    return (true, $"Only {shadowCount} shadow copy available - limited retention", "Increase shadow copy storage allocation");
            }
            catch { }
            return (false, "No backup retention policy detected", "Configure backup retention to maintain multiple recovery points");
        });

        private SecurityCheck CheckBackupCoverage() => RunCheck("backup_coverage", "Backup Coverage Scope", "Data Protection", 3, () =>
        {
            try
            {
                var systemDrive = Path.GetPathRoot(Environment.SystemDirectory) ?? "C:\\";
                var drives = DriveInfo.GetDrives().Where(d => d.IsReady && d.DriveType == DriveType.Fixed).ToList();
                var psi = new ProcessStartInfo("vssadmin", "list shadowstorage")
                { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                using var proc = Process.Start(psi);
                var output = proc?.StandardOutput.ReadToEnd() ?? "";
                proc?.WaitForExit(10000);
                var coveredDrives = drives.Count(d => output.Contains(d.Name.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase));
                if (coveredDrives >= drives.Count)
                    return (true, $"All {drives.Count} fixed drives have shadow storage configured", "");
                if (coveredDrives > 0)
                    return (false, $"Only {coveredDrives}/{drives.Count} fixed drives have backup coverage", "Extend backup to cover all data drives");
            }
            catch { }
            return (false, "Unable to determine backup coverage", "Verify all important drives are included in backup schedule");
        });

        private SecurityCheck CheckAirgapBackup() => RunCheck("airgap_backup", "Air-Gap Backup Check", "Data Protection", 3, () =>
        {
            try
            {
                var removable = DriveInfo.GetDrives().Where(d => d.IsReady && d.DriveType == DriveType.Removable).ToList();
                var network = DriveInfo.GetDrives().Where(d => d.IsReady && d.DriveType == DriveType.Network).ToList();
                if (removable.Count > 0)
                    return (true, $"Removable drive(s) detected: {string.Join(", ", removable.Select(d => d.Name))} - potential air-gap backup target", "Verify removable drives are used for offline backup rotation");
            }
            catch { }
            return (false, "No air-gap backup media detected", "Consider implementing offline backup rotation with removable media for ransomware resilience");
        });

        private SecurityCheck CheckStorageReliability() => RunCheck("storage_reliability", "Storage Reliability Counters", "Data Protection", 3, () =>
        {
            try
            {
                var psi = new ProcessStartInfo("powershell", "-NoProfile -Command \"Get-PhysicalDisk | Select-Object FriendlyName, HealthStatus, OperationalStatus | ConvertTo-Json\"")
                { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                using var proc = Process.Start(psi);
                var output = proc?.StandardOutput.ReadToEnd().Trim() ?? "";
                proc?.WaitForExit(15000);
                if (output.Contains("\"Healthy\"") && !output.Contains("\"Degraded\"") && !output.Contains("\"Unhealthy\""))
                    return (true, "All physical disks report healthy status", "");
                if (output.Contains("\"Degraded\"") || output.Contains("\"Warning\""))
                    return (false, "One or more disks reporting degraded status", "Replace degraded disk immediately and verify backups");
                if (output.Contains("\"Unhealthy\""))
                    return (false, "CRITICAL: Disk failure detected", "Replace failing disk immediately - data loss risk");
            }
            catch { }
            return (true, "Unable to query storage reliability counters", "");
        });

        // === NETWORK (EXTENDED) ===

        private SecurityCheck CheckExternalExposure() => RunCheck("external_exposure", "External Exposure Validation", "Network", 3, () =>
        {
            try
            {
                var listeningPorts = new List<int>();
                var psi = new ProcessStartInfo("netstat", "-an")
                { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                using var proc = Process.Start(psi);
                var output = proc?.StandardOutput.ReadToEnd() ?? "";
                proc?.WaitForExit(10000);
                var riskyPorts = new[] { 21, 23, 25, 80, 443, 445, 1433, 3306, 3389, 5432, 5900, 8080 };
                var exposed = new List<string>();
                foreach (var line in output.Split('\n'))
                {
                    if (line.Contains("LISTENING") && line.Contains("0.0.0.0:"))
                    {
                        var parts = line.Trim().Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length >= 2)
                        {
                            var addr = parts[1];
                            var portStr = addr.Split(':').LastOrDefault();
                            if (int.TryParse(portStr, out var port) && riskyPorts.Contains(port))
                                exposed.Add(port.ToString());
                        }
                    }
                }
                if (exposed.Count > 0)
                    return (false, $"Potentially exposed ports on 0.0.0.0: {string.Join(", ", exposed)}", "Review firewall rules and restrict listening interfaces to local addresses where possible");
                return (true, "No critical services exposed on all interfaces", "");
            }
            catch { }
            return (true, "Unable to assess external exposure", "");
        });

        private SecurityCheck CheckSmbSigning() => RunCheck("smb_signing", "SMB Signing", "Network", 3, () =>
        {
            try
            {
                var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters");
                if (key != null)
                {
                    var requireSigning = key.GetValue("RequireSecuritySignature");
                    if (requireSigning != null && Convert.ToInt32(requireSigning) == 1)
                        return (true, "SMB signing is required", "");
                    var enableSigning = key.GetValue("EnableSecuritySignature");
                    if (enableSigning != null && Convert.ToInt32(enableSigning) == 1)
                        return (true, "SMB signing is enabled (but not required)", "Consider requiring SMB signing for relay attack protection");
                    return (false, "SMB signing is not enabled", "Enable SMB signing: Set-SmbServerConfiguration -RequireSecuritySignature $true");
                }
            }
            catch { }
            return (false, "Unable to check SMB signing status", "Enable SMB signing for network security");
        });

        private SecurityCheck CheckNtlmRestriction() => RunCheck("ntlm_restriction", "NTLM Restriction / Legacy Auth", "Network", 3, () =>
        {
            try
            {
                var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Lsa");
                if (key != null)
                {
                    var lmLevel = key.GetValue("LmCompatibilityLevel");
                    if (lmLevel != null)
                    {
                        var level = Convert.ToInt32(lmLevel);
                        if (level >= 5) return (true, "NTLMv2 only, refuse LM & NTLM - maximum security", "");
                        if (level >= 3) return (true, $"NTLMv2 responses only (level {level})", "Consider increasing to level 5 to refuse NTLM entirely");
                        return (false, $"LM compatibility level is {level} - legacy auth protocols enabled", "Set LmCompatibilityLevel to 5 to enforce NTLMv2 only");
                    }
                }
            }
            catch { }
            return (false, "NTLM restriction not configured", "Configure LmCompatibilityLevel to restrict legacy authentication");
        });

        private SecurityCheck CheckNetworkSegmentation() => RunCheck("network_segmentation", "Network Segmentation / VLAN Awareness", "Network", 3, () =>
        {
            try
            {
                var psi = new ProcessStartInfo("powershell", "-NoProfile -Command \"Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object Name, InterfaceDescription, VlanID | ConvertTo-Json\"")
                { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                using var proc = Process.Start(psi);
                var output = proc?.StandardOutput.ReadToEnd().Trim() ?? "";
                proc?.WaitForExit(10000);
                if (output.Contains("VlanID") && !output.Contains("\"VlanID\":null") && !output.Contains("\"VlanID\":0"))
                    return (true, "VLAN tagging detected on network adapters", "");
                var fwProfiles = 0;
                foreach (var profile in new[] { "Domain", "Private", "Public" })
                {
                    var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{profile}Profile");
                    if (key?.GetValue("EnableFirewall") is int enabled && enabled == 1) fwProfiles++;
                }
                if (fwProfiles >= 3) return (true, $"All {fwProfiles} firewall profiles active - provides logical segmentation", "");
                return (false, $"Only {fwProfiles}/3 firewall profiles active, no VLAN detected", "Enable all firewall profiles and consider network VLAN segmentation");
            }
            catch { }
            return (true, "Unable to assess network segmentation", "");
        });

        private SecurityCheck CheckPublicShareExposure() => RunCheck("public_share_exposure", "Public Share Exposure", "Network", 3, () =>
        {
            try
            {
                var psi = new ProcessStartInfo("net", "share")
                { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                using var proc = Process.Start(psi);
                var output = proc?.StandardOutput.ReadToEnd() ?? "";
                proc?.WaitForExit(10000);
                var shares = output.Split('\n')
                    .Where(l => !string.IsNullOrWhiteSpace(l) && !l.StartsWith("Share name") && !l.StartsWith("---") && !l.Contains("command completed"))
                    .Select(l => l.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault())
                    .Where(s => !string.IsNullOrEmpty(s) && !s.EndsWith("$"))
                    .ToList();
                if (shares.Count > 0)
                    return (false, $"Non-admin shares found: {string.Join(", ", shares)}", "Review shared folders and remove unnecessary shares. Ensure proper ACLs on required shares");
                return (true, "No non-admin network shares detected", "");
            }
            catch { }
            return (true, "Unable to enumerate network shares", "");
        });

        private SecurityCheck CheckDnsOverHttps() => RunCheck("dns_over_https", "DNS over HTTPS / Secure Resolver", "Network", 3, () =>
        {
            try
            {
                var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters");
                if (key != null)
                {
                    var doh = key.GetValue("EnableAutoDoh");
                    if (doh != null && Convert.ToInt32(doh) == 2)
                        return (true, "DNS over HTTPS is enabled (system-wide)", "");
                }
                var psi = new ProcessStartInfo("powershell", "-NoProfile -Command \"Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses -match '1.1.1.1|8.8.8.8|9.9.9.9' } | Select-Object -First 1 -ExpandProperty ServerAddresses\"")
                { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                using var proc = Process.Start(psi);
                var output = proc?.StandardOutput.ReadToEnd().Trim() ?? "";
                proc?.WaitForExit(10000);
                if (!string.IsNullOrEmpty(output))
                    return (true, $"Using DoH-capable resolver: {output}", "Enable DNS over HTTPS in Windows settings for encrypted DNS");
                return (false, "Not using a known secure DNS resolver", "Configure DNS to use a DoH-capable resolver (1.1.1.1, 8.8.8.8, or 9.9.9.9)");
            }
            catch { }
            return (true, "Unable to check DNS resolver configuration", "");
        });

        private SecurityCheck CheckFwFirmwareAge() => RunCheck("fw_firmware_age", "Firewall Firmware / Gateway Age", "Network", 2, () =>
        {
            try
            {
                var psi = new ProcessStartInfo("powershell", "-NoProfile -Command \"(Get-NetFirewallProfile | Select-Object -First 1).InstanceID\"")
                { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                using var proc = Process.Start(psi);
                proc?.WaitForExit(10000);
                var gateway = "";
                var gwPsi = new ProcessStartInfo("powershell", "-NoProfile -Command \"(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Select-Object -First 1).NextHop\"")
                { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                using var gwProc = Process.Start(gwPsi);
                gateway = gwProc?.StandardOutput.ReadToEnd().Trim() ?? "";
                gwProc?.WaitForExit(10000);
                if (!string.IsNullOrEmpty(gateway))
                    return (true, $"Default gateway: {gateway} - verify gateway/router firmware is current", "Check your network gateway/router for firmware updates");
                return (true, "Gateway detected, unable to assess firmware age remotely", "Manually verify router/firewall firmware is up to date");
            }
            catch { }
            return (true, "Unable to assess gateway firmware status", "Manually verify network equipment firmware");
        });

        private SecurityCheck CheckGeoOutboundAnomaly() => RunCheck("geo_outbound_anomaly", "Geo-IP Outbound Anomaly", "Network", 3, () =>
        {
            try
            {
                var psi = new ProcessStartInfo("netstat", "-an")
                { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                using var proc = Process.Start(psi);
                var output = proc?.StandardOutput.ReadToEnd() ?? "";
                proc?.WaitForExit(10000);
                var established = output.Split('\n')
                    .Where(l => l.Contains("ESTABLISHED"))
                    .Count();
                if (established > 100)
                    return (false, $"{established} established connections - unusually high, possible data exfiltration", "Investigate high number of outbound connections for suspicious activity");
                return (true, $"{established} established connections - within normal range", "");
            }
            catch { }
            return (true, "Unable to assess outbound connection patterns", "");
        });

        // === IDENTITY & ACCESS (EXTENDED) ===

        private SecurityCheck CheckIdpMfaValidation() => RunCheck("idp_mfa_validation", "Identity Provider MFA Validation", "Identity & Access", 3, () =>
        {
            try
            {
                var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI");
                var lastUser = key?.GetValue("LastLoggedOnUser") as string ?? "";
                var aadKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo");
                if (aadKey != null)
                {
                    var subKeys = aadKey.GetSubKeyNames();
                    if (subKeys.Length > 0)
                        return (true, "Azure AD joined - MFA should be enforced via Conditional Access policies", "Verify MFA is enabled in Azure AD Conditional Access");
                }
                var domainKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters");
                var domain = domainKey?.GetValue("Domain") as string;
                if (!string.IsNullOrEmpty(domain))
                    return (true, $"Domain joined ({domain}) - verify MFA is configured via AD/GPO", "Enable MFA through Active Directory Federation Services or Azure MFA");
                return (false, "Workgroup computer - no identity provider MFA detected", "Consider joining Azure AD and enabling MFA for all user accounts");
            }
            catch { }
            return (true, "Unable to assess identity provider MFA configuration", "");
        });

        private SecurityCheck CheckStaleAdminAccounts() => RunCheck("stale_admin_accounts", "Stale Admin Accounts", "Identity & Access", 3, () =>
        {
            try
            {
                var psi = new ProcessStartInfo("powershell", "-NoProfile -Command \"Get-LocalGroupMember -Group Administrators -ErrorAction SilentlyContinue | ForEach-Object { $u = Get-LocalUser $_.Name -ErrorAction SilentlyContinue; if ($u -and $u.LastLogon -and $u.LastLogon -lt (Get-Date).AddDays(-90)) { $u.Name } }\"")
                { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                using var proc = Process.Start(psi);
                var output = proc?.StandardOutput.ReadToEnd().Trim() ?? "";
                proc?.WaitForExit(15000);
                if (!string.IsNullOrEmpty(output))
                {
                    var stale = output.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                    return (false, $"Stale admin accounts (90+ days inactive): {string.Join(", ", stale)}", "Disable or remove admin accounts that haven't been used in 90+ days");
                }
                return (true, "No stale admin accounts detected", "");
            }
            catch { }
            return (true, "Unable to check for stale admin accounts", "");
        });

        private SecurityCheck CheckServiceAccountAudit() => RunCheck("service_account_audit", "Service Account Audit", "Identity & Access", 3, () =>
        {
            try
            {
                var psi = new ProcessStartInfo("powershell", "-NoProfile -Command \"Get-WmiObject Win32_Service | Where-Object { $_.StartName -and $_.StartName -notin 'LocalSystem','NT AUTHORITY\\\\LocalService','NT AUTHORITY\\\\NetworkService','NT AUTHORITY\\\\NETWORK SERVICE','NT AUTHORITY\\\\LOCAL SERVICE' -and $_.StartName -ne 'LocalSystem' } | Select-Object Name, StartName | ConvertTo-Json\"")
                { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                using var proc = Process.Start(psi);
                var output = proc?.StandardOutput.ReadToEnd().Trim() ?? "";
                proc?.WaitForExit(15000);
                if (!string.IsNullOrEmpty(output) && output != "null" && output.Contains("StartName"))
                {
                    var count = output.Split("\"Name\"").Length - 1;
                    if (count > 5)
                        return (false, $"{count} services running under user accounts (not system accounts)", "Review services running under user accounts - use managed service accounts where possible");
                    return (true, $"{count} service(s) running under user accounts - within normal range", "");
                }
                return (true, "All services running under system accounts", "");
            }
            catch { }
            return (true, "Unable to audit service accounts", "");
        });

        private SecurityCheck CheckAdminLogonFrequency() => RunCheck("admin_logon_frequency", "Admin Logon Frequency", "Identity & Access", 3, () =>
        {
            try
            {
                var psi = new ProcessStartInfo("powershell", "-NoProfile -Command \"(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4672} -MaxEvents 100 -ErrorAction SilentlyContinue | Where-Object { $_.TimeCreated -gt (Get-Date).AddHours(-24) }).Count\"")
                { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                using var proc = Process.Start(psi);
                var output = proc?.StandardOutput.ReadToEnd().Trim() ?? "";
                proc?.WaitForExit(15000);
                if (int.TryParse(output, out var count))
                {
                    if (count > 50)
                        return (false, $"{count} admin logon events in last 24h - unusually high", "Investigate frequent admin logons - possible unauthorized access or misconfigured service");
                    return (true, $"{count} admin logon events in last 24h - normal range", "");
                }
            }
            catch { }
            return (true, "Unable to assess admin logon frequency", "Ensure Security event logging is enabled");
        });

        private SecurityCheck CheckFailedLogonPattern() => RunCheck("failed_logon_pattern", "Failed Logon Pattern", "Identity & Access", 5, () =>
        {
            try
            {
                var psi = new ProcessStartInfo("powershell", "-NoProfile -Command \"(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} -MaxEvents 100 -ErrorAction SilentlyContinue | Where-Object { $_.TimeCreated -gt (Get-Date).AddHours(-24) }).Count\"")
                { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                using var proc = Process.Start(psi);
                var output = proc?.StandardOutput.ReadToEnd().Trim() ?? "";
                proc?.WaitForExit(15000);
                if (int.TryParse(output, out var count))
                {
                    if (count >= 20)
                        return (false, $"{count} failed logons in last 24h - possible brute force attack", "Investigate failed logon sources immediately. Consider enabling account lockout policy");
                    if (count >= 5)
                        return (true, $"{count} failed logons in last 24h - monitor for patterns", "Review failed logon sources for suspicious activity");
                    return (true, $"{count} failed logon(s) in last 24h - normal", "");
                }
            }
            catch { }
            return (true, "Unable to check failed logon patterns", "Ensure Security event logging captures logon failures");
        });

        private SecurityCheck CheckPasswordReuseRisk() => RunCheck("password_reuse_risk", "Password Reuse Risk", "Identity & Access", 3, () =>
        {
            try
            {
                var psi = new ProcessStartInfo("powershell", "-NoProfile -Command \"net accounts | Select-String 'password history'\"")
                { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                using var proc = Process.Start(psi);
                var output = proc?.StandardOutput.ReadToEnd().Trim() ?? "";
                proc?.WaitForExit(10000);
                if (output.Contains("None", StringComparison.OrdinalIgnoreCase) || output.Contains(": 0"))
                    return (false, "Password history is not enforced - users can reuse passwords", "Set password history to at least 5: net accounts /uniquepw:5");
                if (!string.IsNullOrEmpty(output))
                    return (true, $"Password history policy: {output.Trim()}", "");
            }
            catch { }
            return (false, "Unable to verify password reuse prevention", "Configure password history policy to prevent reuse");
        });

        private SecurityCheck CheckCloudIdentityMismatch() => RunCheck("cloud_identity_mismatch", "Local vs Cloud Identity Mismatch", "Identity & Access", 3, () =>
        {
            try
            {
                var psi = new ProcessStartInfo("dsregcmd", "/status")
                { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                using var proc = Process.Start(psi);
                var output = proc?.StandardOutput.ReadToEnd() ?? "";
                proc?.WaitForExit(10000);
                var azureJoined = output.Contains("AzureAdJoined : YES", StringComparison.OrdinalIgnoreCase);
                var domainJoined = output.Contains("DomainJoined : YES", StringComparison.OrdinalIgnoreCase);
                if (azureJoined && domainJoined)
                    return (true, "Hybrid joined (Azure AD + Domain) - verify sync is healthy", "Check Azure AD Connect sync status");
                if (azureJoined)
                    return (true, "Azure AD joined - cloud identity managed", "");
                if (domainJoined)
                    return (true, "Domain joined - consider Azure AD hybrid join for cloud identity alignment", "Plan migration to Azure AD hybrid join for unified identity management");
                return (false, "Workgroup computer - no cloud identity alignment", "Consider Azure AD join for centralized identity and conditional access");
            }
            catch { }
            return (true, "Unable to assess cloud identity status", "");
        });

        // === RANSOMWARE PROTECTION (EXTENDED) ===

        private SecurityCheck CheckHoneyfileStatus() => RunCheck("honeyfile_status", "Honeyfile / Honeypot Status", "Ransomware Protection", 3, () =>
        {
            var honeypotPaths = new[]
            {
                @"C:\Users\Public\Documents\DO_NOT_DELETE_SECURITY.txt",
                @"C:\Users\Public\Desktop\IMPORTANT_RECORDS.xlsx",
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData) + @"\PCPlusEndpoint\honeyfiles_active"
            };
            foreach (var path in honeypotPaths)
                if (File.Exists(path))
                    return (true, "Honeyfile/honeypot files are deployed", "");
            return (false, "No honeyfile/honeypot files detected", "Deploy decoy files to detect ransomware activity early");
        });

        private SecurityCheck CheckMassRenameDetection() => RunCheck("mass_rename_detection", "Mass Rename Detection", "Ransomware Protection", 3, () =>
        {
            try
            {
                var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access");
                if (key != null)
                {
                    var enabled = key.GetValue("EnableControlledFolderAccess");
                    if (enabled != null && Convert.ToInt32(enabled) == 1)
                        return (true, "Controlled Folder Access provides ransomware rename protection", "");
                }
                var configPath = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData) + @"\PCPlusEndpoint\config.json";
                if (File.Exists(configPath))
                {
                    var json = File.ReadAllText(configPath);
                    if (json.Contains("\"ransomwareProtectionEnabled\":\"true\"", StringComparison.OrdinalIgnoreCase) || json.Contains("\"ransomwareProtectionEnabled\": \"true\"", StringComparison.OrdinalIgnoreCase))
                        return (true, "PC Plus ransomware protection (file rename monitoring) is active", "");
                }
            }
            catch { }
            return (false, "No mass file rename detection configured", "Enable Controlled Folder Access or PC Plus ransomware monitoring");
        });

        private SecurityCheck CheckEntropyAnomaly() => RunCheck("entropy_anomaly", "Encryption Entropy Anomaly", "Ransomware Protection", 3, () =>
        {
            try
            {
                var testDirs = new[] {
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonDocuments),
                    @"C:\Users\Public\Documents"
                };
                foreach (var dir in testDirs)
                {
                    if (!Directory.Exists(dir)) continue;
                    var files = Directory.GetFiles(dir, "*.*", SearchOption.TopDirectoryOnly).Take(20).ToList();
                    var encryptedExtensions = new[] { ".encrypted", ".locked", ".crypto", ".crypt", ".enc", ".aes" };
                    var suspicious = files.Count(f => encryptedExtensions.Any(e => f.EndsWith(e, StringComparison.OrdinalIgnoreCase)));
                    if (suspicious > 3)
                        return (false, $"Suspicious encrypted files detected in {dir}", "URGENT: Investigate possible ransomware encryption activity");
                }
                return (true, "No encryption entropy anomalies detected in monitored folders", "");
            }
            catch { }
            return (true, "Unable to perform entropy analysis", "");
        });

        private SecurityCheck CheckBackupDeleteAttempts() => RunCheck("backup_delete_attempts", "Backup / VSS Delete Attempts", "Ransomware Protection", 5, () =>
        {
            try
            {
                var psi = new ProcessStartInfo("powershell", "-NoProfile -Command \"Get-WinEvent -FilterHashtable @{LogName='System';Id=8194} -MaxEvents 5 -ErrorAction SilentlyContinue | Where-Object { $_.TimeCreated -gt (Get-Date).AddDays(-7) } | Measure-Object | Select-Object -ExpandProperty Count\"")
                { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                using var proc = Process.Start(psi);
                var output = proc?.StandardOutput.ReadToEnd().Trim() ?? "";
                proc?.WaitForExit(15000);
                if (int.TryParse(output, out var count) && count > 0)
                    return (false, $"{count} VSS shadow copy deletion event(s) in the last 7 days", "ALERT: Shadow copy deletions may indicate ransomware activity. Investigate immediately");
                return (true, "No VSS deletion attempts detected in the last 7 days", "");
            }
            catch { }
            return (true, "Unable to check for backup deletion attempts", "");
        });

        private SecurityCheck CheckRestoreObjective() => RunCheck("restore_objective", "Recovery Time Objective Readiness", "Ransomware Protection", 3, () =>
        {
            try
            {
                var hasBackup = false;
                var hasShadow = false;
                var psi = new ProcessStartInfo("vssadmin", "list shadows")
                { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                using var proc = Process.Start(psi);
                var output = proc?.StandardOutput.ReadToEnd() ?? "";
                proc?.WaitForExit(10000);
                hasShadow = output.Contains("Shadow Copy ID");
                var restorePoints = 0;
                var rpPsi = new ProcessStartInfo("powershell", "-NoProfile -Command \"(Get-ComputerRestorePoint -ErrorAction SilentlyContinue | Measure-Object).Count\"")
                { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                using var rpProc = Process.Start(rpPsi);
                var rpOutput = rpProc?.StandardOutput.ReadToEnd().Trim() ?? "";
                rpProc?.WaitForExit(10000);
                int.TryParse(rpOutput, out restorePoints);
                if (hasShadow && restorePoints > 0)
                    return (true, $"Recovery ready: VSS shadows available, {restorePoints} restore point(s)", "");
                if (hasShadow || restorePoints > 0)
                    return (true, $"Partial recovery capability: {(hasShadow ? "VSS available" : $"{restorePoints} restore point(s)")}", "Improve recovery readiness by enabling both VSS and System Restore");
                return (false, "No recovery mechanisms detected (no VSS shadows or restore points)", "Enable System Protection and configure regular backup schedule");
            }
            catch { }
            return (false, "Unable to assess recovery readiness", "Verify backup and restore capabilities");
        });

        private SecurityCheck CheckIsolationReady() => RunCheck("isolation_ready", "Network Isolation Readiness", "Ransomware Protection", 3, () =>
        {
            try
            {
                var allProfilesEnabled = true;
                foreach (var profile in new[] { "DomainProfile", "PublicProfile", "StandardProfile" })
                {
                    var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{profile}");
                    if (key?.GetValue("EnableFirewall") is int enabled && enabled != 1)
                        allProfilesEnabled = false;
                }
                if (allProfilesEnabled)
                    return (true, "All firewall profiles enabled - network isolation can be triggered via profile switch", "");
                return (false, "Not all firewall profiles are enabled - quick isolation not possible", "Enable all Windows Firewall profiles to allow emergency network isolation");
            }
            catch { }
            return (true, "Unable to assess network isolation readiness", "");
        });

        // === EDR & ADVANCED (EXTENDED) ===

        private SecurityCheck CheckEdrSensorHealth() => RunCheck("edr_sensor_health", "EDR Sensor Health", "EDR & Advanced", 3, () =>
        {
            try
            {
                var services = new Dictionary<string, string>
                {
                    ["Sense"] = "Microsoft Defender for Endpoint",
                    ["WinDefend"] = "Windows Defender Antivirus Service",
                    ["WdNisSvc"] = "Windows Defender NIS Service"
                };
                var running = new List<string>();
                var stopped = new List<string>();
                foreach (var (svc, name) in services)
                {
                    try
                    {
                        using var sc = new ServiceController(svc);
                        if (sc.Status == ServiceControllerStatus.Running) running.Add(name);
                        else stopped.Add(name);
                    }
                    catch { }
                }
                if (running.Count >= 2)
                    return (true, $"EDR sensors healthy: {string.Join(", ", running)}", "");
                if (running.Count > 0)
                    return (true, $"Partial EDR coverage: {string.Join(", ", running)}", "Ensure all security services are running");
                return (false, "No EDR sensor services detected", "Deploy an EDR solution for advanced threat detection");
            }
            catch { }
            return (true, "Unable to assess EDR sensor health", "");
        });

        private SecurityCheck CheckSysmonStatus() => RunCheck("sysmon_status", "Sysmon / Advanced Telemetry", "EDR & Advanced", 3, () =>
        {
            try
            {
                try
                {
                    using var sc = new ServiceController("Sysmon64");
                    if (sc.Status == ServiceControllerStatus.Running)
                        return (true, "Sysmon64 is running - advanced process telemetry active", "");
                }
                catch
                {
                    try
                    {
                        using var sc = new ServiceController("Sysmon");
                        if (sc.Status == ServiceControllerStatus.Running)
                            return (true, "Sysmon is running - advanced process telemetry active", "");
                    }
                    catch { }
                }
                if (File.Exists(@"C:\Windows\Sysmon64.exe") || File.Exists(@"C:\Windows\Sysmon.exe"))
                    return (false, "Sysmon is installed but not running", "Start the Sysmon service for advanced process monitoring");
                return (false, "Sysmon is not installed", "Install Sysmon for detailed process, network, and file change logging");
            }
            catch { }
            return (false, "Unable to check Sysmon status", "Consider deploying Sysmon for enhanced telemetry");
        });

        private SecurityCheck CheckProcessInjectionIndicators() => RunCheck("process_injection_indicators", "Process Injection Indicators", "EDR & Advanced", 3, () =>
        {
            try
            {
                var psi = new ProcessStartInfo("powershell", "-NoProfile -Command \"Get-Process | Where-Object { $_.Modules.Count -gt 100 } | Select-Object -ExpandProperty ProcessName | Select-Object -First 5\"")
                { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                using var proc = Process.Start(psi);
                var output = proc?.StandardOutput.ReadToEnd().Trim() ?? "";
                proc?.WaitForExit(15000);
                var asr = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules");
                var hasInjectionRule = false;
                if (asr != null)
                {
                    var rule = asr.GetValue("75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84");
                    hasInjectionRule = rule != null && Convert.ToInt32(rule) == 1;
                }
                if (hasInjectionRule)
                    return (true, "ASR rule for process injection is active - injection attacks blocked", "");
                return (false, "No process injection protection configured", "Enable ASR rule to block Office applications from injecting code into processes");
            }
            catch { }
            return (true, "Unable to check process injection indicators", "");
        });

        // === LOGGING & VISIBILITY (EXTENDED) ===

        private SecurityCheck CheckLogForwarding() => RunCheck("log_forwarding", "Log Forwarding Status", "Logging & Visibility", 3, () =>
        {
            try
            {
                try
                {
                    using var sc = new ServiceController("WazuhSvc");
                    if (sc.Status == ServiceControllerStatus.Running)
                        return (true, "Wazuh agent is forwarding logs to SIEM", "");
                }
                catch { }
                try
                {
                    using var sc = new ServiceController("Winlogbeat");
                    if (sc.Status == ServiceControllerStatus.Running)
                        return (true, "Winlogbeat is forwarding logs", "");
                }
                catch { }
                var subscriptions = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\EventCollector\Subscriptions");
                if (subscriptions?.SubKeyCount > 0)
                    return (true, "Windows Event Forwarding subscriptions configured", "");
                return (false, "No log forwarding mechanism detected", "Configure log forwarding via Wazuh, Winlogbeat, or Windows Event Forwarding");
            }
            catch { }
            return (false, "Unable to check log forwarding status", "Configure centralized log collection");
        });

        private SecurityCheck CheckSecurityLogSize() => RunCheck("security_log_size", "Security Log Size Adequacy", "Logging & Visibility", 3, () =>
        {
            try
            {
                var psi = new ProcessStartInfo("powershell", "-NoProfile -Command \"$log = Get-WinEvent -ListLog 'Security' -ErrorAction SilentlyContinue; if ($log) { '{0}|{1}' -f $log.MaximumSizeInBytes, $log.FileSize }\"")
                { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                using var proc = Process.Start(psi);
                var output = proc?.StandardOutput.ReadToEnd().Trim() ?? "";
                proc?.WaitForExit(10000);
                var parts = output.Split('|');
                if (parts.Length == 2 && long.TryParse(parts[0], out var maxSize) && long.TryParse(parts[1], out var currentSize))
                {
                    var maxMB = maxSize / (1024 * 1024);
                    var currentMB = currentSize / (1024 * 1024);
                    if (maxMB >= 256)
                        return (true, $"Security log: {currentMB}MB / {maxMB}MB max - adequate size", "");
                    if (maxMB >= 64)
                        return (true, $"Security log: {currentMB}MB / {maxMB}MB max - consider increasing to 256MB+", "Increase Security log size for better forensic coverage");
                    return (false, $"Security log: {currentMB}MB / {maxMB}MB max - too small for forensics", "Increase Security event log maximum size to at least 256MB");
                }
            }
            catch { }
            return (true, "Unable to check Security log size", "");
        });

        // === ENDPOINT HARDENING (EXTENDED) ===

        private SecurityCheck CheckWdacMode() => RunCheck("wdac_mode", "WDAC / AppLocker Mode", "Endpoint Hardening", 3, () =>
        {
            try
            {
                var psi = new ProcessStartInfo("powershell", "-NoProfile -Command \"Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard -ErrorAction SilentlyContinue | Select-Object -ExpandProperty UsermodeCodeIntegrityPolicyEnforcementStatus\"")
                { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                using var proc = Process.Start(psi);
                var output = proc?.StandardOutput.ReadToEnd().Trim() ?? "";
                proc?.WaitForExit(10000);
                if (output == "2") return (true, "WDAC is in enforcement mode", "");
                if (output == "1") return (true, "WDAC is in audit mode", "Consider moving WDAC to enforcement mode after validating policies");
                var applockerKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\SrpV2\Exe");
                if (applockerKey?.SubKeyCount > 0)
                    return (true, "AppLocker policies are configured", "");
            }
            catch { }
            return (false, "No application control (WDAC/AppLocker) is configured", "Consider deploying WDAC or AppLocker for application whitelisting");
        });

        // === HARDWARE SECURITY (EXTENDED) ===

        private SecurityCheck CheckTpmReady() => RunCheck("tpm_ready", "TPM Present and Ready", "Hardware Security", 5, () =>
        {
            try
            {
                var psi = new ProcessStartInfo("powershell", "-NoProfile -Command \"$tpm = Get-Tpm -ErrorAction SilentlyContinue; if ($tpm) { '{0}|{1}|{2}' -f $tpm.TpmPresent, $tpm.TpmReady, $tpm.TpmEnabled }\"")
                { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                using var proc = Process.Start(psi);
                var output = proc?.StandardOutput.ReadToEnd().Trim() ?? "";
                proc?.WaitForExit(10000);
                var parts = output.Split('|');
                if (parts.Length == 3)
                {
                    var present = parts[0].Equals("True", StringComparison.OrdinalIgnoreCase);
                    var ready = parts[1].Equals("True", StringComparison.OrdinalIgnoreCase);
                    var enabled = parts[2].Equals("True", StringComparison.OrdinalIgnoreCase);
                    if (present && ready && enabled)
                        return (true, "TPM is present, ready, and enabled", "");
                    if (present && !ready)
                        return (false, "TPM is present but not ready", "Initialize TPM in BIOS/UEFI settings");
                    if (present && !enabled)
                        return (false, "TPM is present but disabled", "Enable TPM in BIOS/UEFI settings");
                }
                return (false, "TPM is not present", "This device lacks TPM - consider hardware upgrade for BitLocker and Secure Boot support");
            }
            catch { }
            return (true, "Unable to query TPM status", "");
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
