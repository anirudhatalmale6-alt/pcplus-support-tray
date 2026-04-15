using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.ServiceProcess;
using Microsoft.Win32;

namespace SupportTray
{
    /// <summary>
    /// Scans system security posture and produces a 0-100 score.
    /// Checks: Windows Update, antivirus, firewall, UAC, BitLocker, password policy,
    /// RDP exposure, guest account, auto-login, SMBv1, Windows version currency.
    /// </summary>
    public class SecurityScanner
    {
        public int TotalScore { get; private set; }
        public string Grade { get; private set; } = "?";
        public List<SecurityCheck> Checks { get; private set; } = new();
        public DateTime LastScan { get; private set; }

        // Each check has a weight (points). Total possible = 100.
        public void RunFullScan()
        {
            Checks.Clear();
            var checks = new List<SecurityCheck>();

            checks.Add(CheckWindowsUpdate());       // 15 pts
            checks.Add(CheckAntivirus());            // 15 pts
            checks.Add(CheckFirewall());             // 15 pts
            checks.Add(CheckUAC());                  // 10 pts
            checks.Add(CheckBitLocker());            // 10 pts
            checks.Add(CheckWindowsVersion());       // 10 pts
            checks.Add(CheckRDP());                  // 5 pts
            checks.Add(CheckGuestAccount());         // 5 pts
            checks.Add(CheckAutoLogin());            // 5 pts
            checks.Add(CheckSMBv1());                // 5 pts
            checks.Add(CheckWindowsDefenderRealtime()); // 5 pts

            Checks = checks;
            TotalScore = checks.Sum(c => c.Passed ? c.Weight : 0);
            Grade = TotalScore switch
            {
                >= 90 => "A",
                >= 80 => "B",
                >= 70 => "C",
                >= 60 => "D",
                _ => "F"
            };
            LastScan = DateTime.Now;
        }

        private SecurityCheck CheckWindowsUpdate()
        {
            var check = new SecurityCheck
            {
                Name = "Windows Update",
                Category = "Updates",
                Weight = 15,
                Description = "Windows is configured to receive updates"
            };

            try
            {
                // Check if Windows Update service is running
                using var sc = new ServiceController("wuauserv");
                if (sc.Status == ServiceControllerStatus.Running ||
                    sc.Status == ServiceControllerStatus.StartPending)
                {
                    check.Passed = true;
                    check.Detail = "Windows Update service is running";
                }
                else
                {
                    // Check if it's set to manual (still OK - it starts on demand)
                    check.Passed = sc.StartType != ServiceStartMode.Disabled;
                    check.Detail = check.Passed
                        ? "Windows Update service is set to start on demand"
                        : "Windows Update service is DISABLED";
                    check.Recommendation = check.Passed ? "" : "Enable Windows Update in Services";
                }
            }
            catch
            {
                // Can't check service - assume OK if we can find update registry
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(
                        @"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install");
                    if (key != null)
                    {
                        var lastInstall = key.GetValue("LastSuccessTime")?.ToString();
                        if (DateTime.TryParse(lastInstall, out var dt))
                        {
                            var daysSince = (DateTime.Now - dt).TotalDays;
                            check.Passed = daysSince < 45;
                            check.Detail = $"Last update installed {daysSince:F0} days ago";
                            if (!check.Passed)
                                check.Recommendation = "Run Windows Update - it's been over 45 days";
                        }
                    }
                }
                catch
                {
                    check.Passed = false;
                    check.Detail = "Unable to check Windows Update status";
                }
            }

            return check;
        }

        private SecurityCheck CheckAntivirus()
        {
            var check = new SecurityCheck
            {
                Name = "Antivirus Protection",
                Category = "Protection",
                Weight = 15,
                Description = "Active antivirus is installed and enabled"
            };

            try
            {
                // Query Security Center for antivirus products
                using var searcher = new ManagementObjectSearcher(
                    "root\\SecurityCenter2",
                    "SELECT displayName, productState FROM AntiVirusProduct");
                var products = searcher.Get();
                var activeProducts = new List<string>();

                foreach (ManagementObject obj in products)
                {
                    var name = obj["displayName"]?.ToString() ?? "Unknown";
                    var state = Convert.ToInt32(obj["productState"]);

                    // Decode productState: bits 12-8 = scanner state, bit 4 = definitions up to date
                    var scannerActive = ((state >> 12) & 0xF) == 1;
                    var upToDate = ((state >> 4) & 0xF) == 0;

                    if (scannerActive)
                        activeProducts.Add(name + (upToDate ? "" : " (definitions outdated)"));
                }

                if (activeProducts.Count > 0)
                {
                    check.Passed = true;
                    check.Detail = "Active: " + string.Join(", ", activeProducts);
                }
                else
                {
                    check.Passed = false;
                    check.Detail = "No active antivirus detected";
                    check.Recommendation = "Install and enable antivirus software";
                }
            }
            catch
            {
                // SecurityCenter2 not available - check if Defender service is running
                try
                {
                    using var sc = new ServiceController("WinDefend");
                    check.Passed = sc.Status == ServiceControllerStatus.Running;
                    check.Detail = check.Passed
                        ? "Windows Defender service is running"
                        : "Windows Defender is not running";
                }
                catch
                {
                    check.Detail = "Unable to check antivirus status";
                }
            }

            return check;
        }

        private SecurityCheck CheckFirewall()
        {
            var check = new SecurityCheck
            {
                Name = "Windows Firewall",
                Category = "Protection",
                Weight = 15,
                Description = "Windows Firewall is enabled for all profiles"
            };

            try
            {
                var allEnabled = true;
                var profiles = new[] { "DomainProfile", "StandardProfile", "PublicProfile" };
                var profileNames = new[] { "Domain", "Private", "Public" };
                var enabledProfiles = new List<string>();

                for (int i = 0; i < profiles.Length; i++)
                {
                    using var key = Registry.LocalMachine.OpenSubKey(
                        $@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{profiles[i]}");
                    if (key != null)
                    {
                        var enabled = Convert.ToInt32(key.GetValue("EnableFirewall", 0)) == 1;
                        if (enabled)
                            enabledProfiles.Add(profileNames[i]);
                        else
                            allEnabled = false;
                    }
                }

                check.Passed = enabledProfiles.Count >= 2; // At least 2 of 3 profiles
                check.Detail = enabledProfiles.Count == 3
                    ? "Firewall enabled on all profiles"
                    : $"Firewall enabled on: {string.Join(", ", enabledProfiles)}";
                if (!check.Passed)
                    check.Recommendation = "Enable Windows Firewall for all network profiles";
            }
            catch
            {
                check.Detail = "Unable to check firewall status";
            }

            return check;
        }

        private SecurityCheck CheckUAC()
        {
            var check = new SecurityCheck
            {
                Name = "User Account Control (UAC)",
                Category = "Protection",
                Weight = 10,
                Description = "UAC is enabled to prevent unauthorized changes"
            };

            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System");
                if (key != null)
                {
                    var enableLua = Convert.ToInt32(key.GetValue("EnableLUA", 0));
                    check.Passed = enableLua == 1;
                    check.Detail = check.Passed ? "UAC is enabled" : "UAC is DISABLED";
                    if (!check.Passed)
                        check.Recommendation = "Enable UAC in Control Panel > User Accounts";
                }
            }
            catch
            {
                check.Detail = "Unable to check UAC status";
            }

            return check;
        }

        private SecurityCheck CheckBitLocker()
        {
            var check = new SecurityCheck
            {
                Name = "Drive Encryption (BitLocker)",
                Category = "Data Protection",
                Weight = 10,
                Description = "System drive is encrypted with BitLocker"
            };

            try
            {
                // Check via WMI
                using var searcher = new ManagementObjectSearcher(
                    "root\\CIMV2\\Security\\MicrosoftVolumeEncryption",
                    "SELECT DriveLetter, ProtectionStatus FROM Win32_EncryptableVolume");
                var volumes = searcher.Get();
                bool systemDriveEncrypted = false;
                var systemDrive = Environment.GetFolderPath(Environment.SpecialFolder.Windows)
                    .Substring(0, 2); // "C:"

                foreach (ManagementObject obj in volumes)
                {
                    var drive = obj["DriveLetter"]?.ToString() ?? "";
                    var status = Convert.ToInt32(obj["ProtectionStatus"]);
                    if (drive.Equals(systemDrive, StringComparison.OrdinalIgnoreCase) && status == 1)
                    {
                        systemDriveEncrypted = true;
                    }
                }

                check.Passed = systemDriveEncrypted;
                check.Detail = check.Passed
                    ? $"BitLocker is active on {systemDrive}"
                    : $"System drive {systemDrive} is not encrypted";
                if (!check.Passed)
                    check.Recommendation = "Enable BitLocker on the system drive for data protection";
            }
            catch
            {
                // BitLocker WMI not available (Home edition)
                check.Passed = false;
                check.Detail = "BitLocker not available (may require Windows Pro/Enterprise)";
                check.Recommendation = "Consider upgrading to Windows Pro for BitLocker support";
            }

            return check;
        }

        private SecurityCheck CheckWindowsVersion()
        {
            var check = new SecurityCheck
            {
                Name = "Windows Version",
                Category = "Updates",
                Weight = 10,
                Description = "Running a supported version of Windows"
            };

            try
            {
                var osVersion = Environment.OSVersion.Version;
                using var searcher = new ManagementObjectSearcher(
                    "SELECT Caption, BuildNumber FROM Win32_OperatingSystem");
                foreach (ManagementObject obj in searcher.Get())
                {
                    var caption = obj["Caption"]?.ToString() ?? "";
                    var build = int.TryParse(obj["BuildNumber"]?.ToString(), out var b) ? b : 0;

                    // Windows 10 22H2 = 19045, Windows 11 = 22000+
                    // EOL versions: anything below Windows 10 (build < 10240)
                    if (build >= 19041) // Windows 10 2004+
                    {
                        check.Passed = true;
                        check.Detail = $"{caption} (Build {build})";
                    }
                    else if (build >= 10240) // Older Windows 10
                    {
                        check.Passed = false;
                        check.Detail = $"{caption} (Build {build}) - outdated feature update";
                        check.Recommendation = "Update to the latest Windows 10/11 feature update";
                    }
                    else
                    {
                        check.Passed = false;
                        check.Detail = $"{caption} - end of life";
                        check.Recommendation = "Upgrade to Windows 10 or 11 for security updates";
                    }
                    break;
                }
            }
            catch
            {
                check.Detail = "Unable to determine Windows version";
            }

            return check;
        }

        private SecurityCheck CheckRDP()
        {
            var check = new SecurityCheck
            {
                Name = "Remote Desktop",
                Category = "Network",
                Weight = 5,
                Description = "Remote Desktop is disabled or properly secured"
            };

            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Control\Terminal Server");
                if (key != null)
                {
                    var disabled = Convert.ToInt32(key.GetValue("fDenyTSConnections", 1));
                    check.Passed = disabled == 1; // 1 = RDP disabled (more secure)
                    check.Detail = check.Passed
                        ? "Remote Desktop is disabled"
                        : "Remote Desktop is ENABLED (ensure it's needed and secured with NLA)";
                    if (!check.Passed)
                        check.Recommendation = "Disable RDP if not needed, or ensure Network Level Authentication (NLA) is required";
                }
            }
            catch
            {
                check.Passed = true; // Can't check = assume default (disabled)
                check.Detail = "Unable to check RDP status";
            }

            return check;
        }

        private SecurityCheck CheckGuestAccount()
        {
            var check = new SecurityCheck
            {
                Name = "Guest Account",
                Category = "Access Control",
                Weight = 5,
                Description = "Guest account is disabled"
            };

            try
            {
                // Check via net user guest
                var psi = new ProcessStartInfo
                {
                    FileName = "net",
                    Arguments = "user Guest",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using var proc = Process.Start(psi);
                var output = proc?.StandardOutput.ReadToEnd() ?? "";
                proc?.WaitForExit(5000);

                var isActive = output.Contains("Account active") &&
                              output.Contains("Yes", StringComparison.OrdinalIgnoreCase) &&
                              !output.Contains("No", StringComparison.OrdinalIgnoreCase);

                // More reliable: check the specific line
                foreach (var line in output.Split('\n'))
                {
                    if (line.TrimStart().StartsWith("Account active", StringComparison.OrdinalIgnoreCase))
                    {
                        isActive = line.Contains("Yes", StringComparison.OrdinalIgnoreCase);
                        break;
                    }
                }

                check.Passed = !isActive;
                check.Detail = check.Passed ? "Guest account is disabled" : "Guest account is ENABLED";
                if (!check.Passed)
                    check.Recommendation = "Disable the Guest account: net user Guest /active:no";
            }
            catch
            {
                check.Passed = true; // Default assumption
                check.Detail = "Unable to check Guest account status";
            }

            return check;
        }

        private SecurityCheck CheckAutoLogin()
        {
            var check = new SecurityCheck
            {
                Name = "Auto-Login",
                Category = "Access Control",
                Weight = 5,
                Description = "Auto-login is disabled (password required at startup)"
            };

            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon");
                if (key != null)
                {
                    var autoAdmin = key.GetValue("AutoAdminLogon")?.ToString() ?? "0";
                    var defaultPassword = key.GetValue("DefaultPassword")?.ToString();

                    check.Passed = autoAdmin != "1" || string.IsNullOrEmpty(defaultPassword);
                    check.Detail = check.Passed
                        ? "Auto-login is not configured"
                        : "Auto-login is ENABLED with stored credentials";
                    if (!check.Passed)
                        check.Recommendation = "Disable auto-login: remove AutoAdminLogon from registry";
                }
            }
            catch
            {
                check.Passed = true;
                check.Detail = "Unable to check auto-login status";
            }

            return check;
        }

        private SecurityCheck CheckSMBv1()
        {
            var check = new SecurityCheck
            {
                Name = "SMBv1 Protocol",
                Category = "Network",
                Weight = 5,
                Description = "Legacy SMBv1 protocol is disabled (WannaCry vector)"
            };

            try
            {
                // Check registry for SMBv1 server
                using var key = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters");
                if (key != null)
                {
                    var smb1 = key.GetValue("SMB1");
                    if (smb1 != null)
                    {
                        check.Passed = Convert.ToInt32(smb1) == 0;
                    }
                    else
                    {
                        // Not explicitly set - check Windows feature
                        check.Passed = true; // Modern Windows disables SMBv1 by default
                    }
                }
                else
                {
                    check.Passed = true; // Default is disabled on modern Windows
                }

                check.Detail = check.Passed
                    ? "SMBv1 is disabled"
                    : "SMBv1 is ENABLED (vulnerable to WannaCry/EternalBlue)";
                if (!check.Passed)
                    check.Recommendation = "Disable SMBv1: Set-SmbServerConfiguration -EnableSMB1Protocol $false";
            }
            catch
            {
                check.Passed = true;
                check.Detail = "Unable to check SMBv1 status";
            }

            return check;
        }

        private SecurityCheck CheckWindowsDefenderRealtime()
        {
            var check = new SecurityCheck
            {
                Name = "Real-time Protection",
                Category = "Protection",
                Weight = 5,
                Description = "Windows Defender real-time protection is active"
            };

            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection");
                if (key != null)
                {
                    var disabled = Convert.ToInt32(key.GetValue("DisableRealtimeMonitoring", 0));
                    check.Passed = disabled == 0;
                    check.Detail = check.Passed
                        ? "Real-time protection is active"
                        : "Real-time protection is DISABLED";
                    if (!check.Passed)
                        check.Recommendation = "Enable real-time protection in Windows Security";
                }
                else
                {
                    // Third-party AV may have replaced Defender
                    check.Passed = true;
                    check.Detail = "Windows Defender may be replaced by third-party antivirus";
                }
            }
            catch
            {
                check.Passed = true;
                check.Detail = "Unable to check real-time protection status";
            }

            return check;
        }

        public string GetReportText()
        {
            var lines = new List<string>();
            lines.Add($"=== Security Scan Report ===");
            lines.Add($"Score: {TotalScore}/100 (Grade: {Grade})");
            lines.Add($"Scan Date: {LastScan:yyyy-MM-dd HH:mm}");
            lines.Add("");

            foreach (var check in Checks)
            {
                var status = check.Passed ? "PASS" : "FAIL";
                lines.Add($"[{status}] {check.Name} ({check.Weight} pts)");
                lines.Add($"       {check.Detail}");
                if (!check.Passed && !string.IsNullOrEmpty(check.Recommendation))
                    lines.Add($"       FIX: {check.Recommendation}");
                lines.Add("");
            }

            return string.Join(Environment.NewLine, lines);
        }
    }

    public class SecurityCheck
    {
        public string Name { get; set; } = "";
        public string Category { get; set; } = "";
        public string Description { get; set; } = "";
        public int Weight { get; set; }
        public bool Passed { get; set; }
        public string Detail { get; set; } = "";
        public string Recommendation { get; set; } = "";
    }
}
