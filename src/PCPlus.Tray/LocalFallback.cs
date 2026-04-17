using System.Diagnostics;
using System.Management;
using System.Net.NetworkInformation;
using PCPlus.Core.Models;

namespace PCPlus.Tray
{
    /// <summary>
    /// Provides direct health monitoring, security scanning, and maintenance
    /// when the PCPlus.Service Windows Service is not available.
    /// This ensures the tray app works standalone without the service.
    /// </summary>
    public class LocalFallback : IDisposable
    {
        private PerformanceCounter? _cpuCounter;
        private HealthSnapshot _current = new();
        private SecurityScanResult? _lastScanResult;
        private readonly object _lock = new();
        private Timer? _pollTimer;
        private bool _disposed;

        // Network tracking
        private long _lastBytesSent;
        private long _lastBytesRecv;
        private DateTime _lastNetworkCheck = DateTime.MinValue;

        public HealthSnapshot CurrentHealth
        {
            get { lock (_lock) return _current; }
        }

        public SecurityScanResult? LastSecurityScan => _lastScanResult;

        public void Start()
        {
            try
            {
                _cpuCounter = new PerformanceCounter("Processor", "% Processor Time", "_Total");
                _cpuCounter.NextValue(); // First call always returns 0
            }
            catch { _cpuCounter = null; }

            _pollTimer = new Timer(Poll, null, 1000, 2000);
        }

        private void Poll(object? state)
        {
            try
            {
                var snap = new HealthSnapshot { Timestamp = DateTime.UtcNow };

                // CPU
                try { snap.CpuPercent = _cpuCounter?.NextValue() ?? GetCpuViaWmi(); }
                catch { snap.CpuPercent = GetCpuViaWmi(); }

                // RAM
                PollRam(snap);

                // Disks
                PollDisks(snap);

                // Temps
                PollTemps(snap);

                // Network
                PollNetwork(snap);

                // Processes
                PollProcesses(snap);

                // Uptime
                snap.Uptime = TimeSpan.FromMilliseconds(Environment.TickCount64);

                lock (_lock) _current = snap;
            }
            catch { }
        }

        private float GetCpuViaWmi()
        {
            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT LoadPercentage FROM Win32_Processor");
                foreach (ManagementObject obj in searcher.Get())
                    return Convert.ToSingle(obj["LoadPercentage"]);
            }
            catch { }
            return 0;
        }

        private void PollRam(HealthSnapshot snap)
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    "SELECT TotalVisibleMemorySize, FreePhysicalMemory FROM Win32_OperatingSystem");
                foreach (ManagementObject obj in searcher.Get())
                {
                    var totalKB = Convert.ToDouble(obj["TotalVisibleMemorySize"]);
                    var freeKB = Convert.ToDouble(obj["FreePhysicalMemory"]);
                    snap.RamTotalGB = (float)(totalKB / 1024.0 / 1024.0);
                    snap.RamUsedGB = (float)((totalKB - freeKB) / 1024.0 / 1024.0);
                    snap.RamPercent = (float)((totalKB - freeKB) / totalKB * 100.0);
                    break;
                }
            }
            catch { }
        }

        private void PollDisks(HealthSnapshot snap)
        {
            try
            {
                foreach (var drive in DriveInfo.GetDrives())
                {
                    if (drive.IsReady && drive.DriveType == DriveType.Fixed)
                    {
                        var totalGB = drive.TotalSize / (1024.0 * 1024 * 1024);
                        var freeGB = drive.AvailableFreeSpace / (1024.0 * 1024 * 1024);
                        snap.Disks.Add(new DiskReading
                        {
                            Name = drive.Name.TrimEnd('\\'),
                            Label = drive.VolumeLabel,
                            TotalGB = (float)totalGB,
                            FreeGB = (float)freeGB,
                            UsedPercent = (float)(((totalGB - freeGB) / totalGB) * 100)
                        });
                    }
                }
            }
            catch { }
        }

        private void PollTemps(HealthSnapshot snap)
        {
            if (TryWmiTemps(snap, "root\\LibreHardwareMonitor")) return;
            if (TryWmiTemps(snap, "root\\OpenHardwareMonitor")) return;
            TryAcpiTemp(snap);
        }

        private bool TryWmiTemps(HealthSnapshot snap, string ns)
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(ns,
                    "SELECT Value, Name, Parent FROM Sensor WHERE SensorType='Temperature'");
                bool found = false;
                foreach (ManagementObject obj in searcher.Get())
                {
                    var name = obj["Name"]?.ToString() ?? "";
                    var parent = obj["Parent"]?.ToString() ?? "";
                    var value = Convert.ToSingle(obj["Value"]);

                    if (snap.CpuTempC == 0 && (name.Contains("CPU", StringComparison.OrdinalIgnoreCase) ||
                        name.Contains("Core", StringComparison.OrdinalIgnoreCase) ||
                        parent.Contains("cpu", StringComparison.OrdinalIgnoreCase)))
                    {
                        snap.CpuTempC = value;
                        snap.CpuTempSource = name;
                        found = true;
                    }
                    if (snap.GpuTempC == 0 && (name.Contains("GPU", StringComparison.OrdinalIgnoreCase) ||
                        parent.Contains("gpu", StringComparison.OrdinalIgnoreCase) ||
                        parent.Contains("nvidia", StringComparison.OrdinalIgnoreCase) ||
                        parent.Contains("amd", StringComparison.OrdinalIgnoreCase)))
                    {
                        snap.GpuTempC = value;
                        snap.GpuTempSource = name;
                        found = true;
                    }
                }
                return found;
            }
            catch { return false; }
        }

        private void TryAcpiTemp(HealthSnapshot snap)
        {
            try
            {
                using var searcher = new ManagementObjectSearcher("root\\WMI",
                    "SELECT CurrentTemperature FROM MSAcpi_ThermalZoneTemperature");
                foreach (ManagementObject obj in searcher.Get())
                {
                    var tempK = Convert.ToDouble(obj["CurrentTemperature"]) / 10.0;
                    var tempC = (float)(tempK - 273.15);
                    if (tempC > 0 && tempC < 120)
                    {
                        snap.CpuTempC = tempC;
                        snap.CpuTempSource = "ACPI Thermal Zone";
                    }
                    break;
                }
            }
            catch { }
        }

        private void PollNetwork(HealthSnapshot snap)
        {
            try
            {
                long totalSent = 0, totalRecv = 0;
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus == OperationalStatus.Up &&
                        ni.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                    {
                        var stats = ni.GetIPv4Statistics();
                        totalSent += stats.BytesSent;
                        totalRecv += stats.BytesReceived;
                    }
                }

                var now = DateTime.UtcNow;
                if (_lastNetworkCheck != DateTime.MinValue)
                {
                    var elapsed = (now - _lastNetworkCheck).TotalSeconds;
                    if (elapsed > 0)
                    {
                        snap.NetworkSentKBps = (float)((totalSent - _lastBytesSent) / 1024.0 / elapsed);
                        snap.NetworkRecvKBps = (float)((totalRecv - _lastBytesRecv) / 1024.0 / elapsed);
                    }
                }
                _lastBytesSent = totalSent;
                _lastBytesRecv = totalRecv;
                _lastNetworkCheck = now;
            }
            catch { }
        }

        private void PollProcesses(HealthSnapshot snap)
        {
            try
            {
                var procs = Process.GetProcesses();
                snap.ProcessCount = procs.Length;
                snap.TopProcesses = procs
                    .Where(p => { try { return p.WorkingSet64 > 0; } catch { return false; } })
                    .OrderByDescending(p => { try { return p.WorkingSet64; } catch { return 0L; } })
                    .Take(8)
                    .Select(p =>
                    {
                        try
                        {
                            return new ProcessReading
                            {
                                Name = p.ProcessName,
                                MemoryMB = (float)(p.WorkingSet64 / (1024.0 * 1024)),
                                Pid = p.Id
                            };
                        }
                        catch { return null; }
                    })
                    .Where(p => p != null)
                    .ToList()!;
                foreach (var p in procs) try { p.Dispose(); } catch { }
            }
            catch { }
        }

        #region Security Scanning

        public async Task<SecurityScanResult> RunSecurityScanAsync()
        {
            return await Task.Run(() =>
            {
                var result = new SecurityScanResult
                {
                    ScanTime = DateTime.Now,
                    Checks = new List<SecurityCheck>()
                };

                int totalScore = 0;

                // 1. Windows Update (15 pts)
                var wuCheck = CheckWindowsUpdate();
                result.Checks.Add(wuCheck);
                if (wuCheck.Passed) totalScore += 15;

                // 2. Antivirus (15 pts)
                var avCheck = CheckAntivirus();
                result.Checks.Add(avCheck);
                if (avCheck.Passed) totalScore += 15;

                // 3. Firewall (15 pts)
                var fwCheck = CheckFirewall();
                result.Checks.Add(fwCheck);
                if (fwCheck.Passed) totalScore += 15;

                // 4. UAC (10 pts)
                var uacCheck = CheckUAC();
                result.Checks.Add(uacCheck);
                if (uacCheck.Passed) totalScore += 10;

                // 5. BitLocker (10 pts)
                var blCheck = CheckBitLocker();
                result.Checks.Add(blCheck);
                if (blCheck.Passed) totalScore += 10;

                // 6. Windows Version (10 pts)
                var verCheck = CheckWindowsVersion();
                result.Checks.Add(verCheck);
                if (verCheck.Passed) totalScore += 10;

                // 7. RDP (5 pts)
                var rdpCheck = CheckRDP();
                result.Checks.Add(rdpCheck);
                if (rdpCheck.Passed) totalScore += 5;

                // 8. Guest Account (5 pts)
                var guestCheck = CheckGuestAccount();
                result.Checks.Add(guestCheck);
                if (guestCheck.Passed) totalScore += 5;

                // 9. Auto-Login (5 pts)
                var autoCheck = CheckAutoLogin();
                result.Checks.Add(autoCheck);
                if (autoCheck.Passed) totalScore += 5;

                // 10. SMBv1 (5 pts)
                var smbCheck = CheckSMBv1();
                result.Checks.Add(smbCheck);
                if (smbCheck.Passed) totalScore += 5;

                // 11. Real-time Protection (5 pts)
                var rtpCheck = CheckRealtimeProtection();
                result.Checks.Add(rtpCheck);
                if (rtpCheck.Passed) totalScore += 5;

                // 12. Tactical RMM Agent (bonus - adds to score beyond 100 baseline)
                var trmmCheck = CheckTacticalRmmAgent();
                result.Checks.Add(trmmCheck);

                // 13. Wazuh Agent (bonus - adds to score beyond 100 baseline)
                var wazuhCheck = CheckWazuhAgent();
                result.Checks.Add(wazuhCheck);

                // Bonus: if both RMM tools are running, add bonus points (max stays 100)
                // Penalty: if either is missing, deduct from score to flag it
                if (!trmmCheck.Passed) totalScore = Math.Max(0, totalScore - 5);
                if (!wazuhCheck.Passed) totalScore = Math.Max(0, totalScore - 5);

                result.TotalScore = Math.Min(totalScore, 100);
                result.Grade = totalScore >= 90 ? "A" : totalScore >= 80 ? "B" :
                    totalScore >= 70 ? "C" : totalScore >= 60 ? "D" : "F";

                _lastScanResult = result;
                return result;
            });
        }

        private SecurityCheck CheckWindowsUpdate()
        {
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install");
                if (key != null)
                {
                    var lastStr = key.GetValue("LastSuccessTime")?.ToString();
                    if (DateTime.TryParse(lastStr, out var lastUpdate))
                    {
                        var daysOld = (DateTime.Now - lastUpdate).TotalDays;
                        return new SecurityCheck
                        {
                            Name = "Windows Update",
                            Category = "System Updates",
                            Passed = daysOld < 30,
                            Detail = daysOld < 30 ? $"Last updated {daysOld:F0} days ago" : $"Last updated {daysOld:F0} days ago - overdue",
                            Recommendation = daysOld >= 30 ? "Run Windows Update to install latest patches" : ""
                        };
                    }
                }
            }
            catch { }
            // Fallback: check if Windows Update service is running
            try
            {
                var sc = new System.ServiceProcess.ServiceController("wuauserv");
                return new SecurityCheck
                {
                    Name = "Windows Update",
                    Category = "System Updates",
                    Passed = sc.Status != System.ServiceProcess.ServiceControllerStatus.Stopped,
                    Detail = sc.Status != System.ServiceProcess.ServiceControllerStatus.Stopped
                        ? "Windows Update service is running"
                        : "Windows Update service is stopped",
                    Recommendation = "Enable Windows Update service"
                };
            }
            catch
            {
                return new SecurityCheck
                {
                    Name = "Windows Update",
                    Category = "System Updates",
                    Passed = false,
                    Detail = "Could not check Windows Update status",
                    Recommendation = "Verify Windows Update is enabled"
                };
            }
        }

        private SecurityCheck CheckAntivirus()
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(@"root\SecurityCenter2",
                    "SELECT displayName, productState FROM AntiVirusProduct");
                foreach (ManagementObject obj in searcher.Get())
                {
                    var name = obj["displayName"]?.ToString() ?? "Unknown";
                    var state = Convert.ToInt32(obj["productState"]);
                    var enabled = ((state >> 12) & 0xF) == 1;
                    var upToDate = ((state >> 4) & 0xF) == 0;
                    return new SecurityCheck
                    {
                        Name = "Antivirus Protection",
                        Category = "Security Software",
                        Passed = enabled,
                        Detail = enabled ? $"{name} is active and {(upToDate ? "up to date" : "needs updating")}"
                            : $"{name} is installed but not active",
                        Recommendation = !enabled ? "Enable your antivirus protection" : ""
                    };
                }
            }
            catch { }
            // Fallback: check Windows Defender
            try
            {
                var sc = new System.ServiceProcess.ServiceController("WinDefend");
                return new SecurityCheck
                {
                    Name = "Antivirus Protection",
                    Category = "Security Software",
                    Passed = sc.Status == System.ServiceProcess.ServiceControllerStatus.Running,
                    Detail = sc.Status == System.ServiceProcess.ServiceControllerStatus.Running
                        ? "Windows Defender is running"
                        : "Windows Defender is not running",
                    Recommendation = "Enable Windows Defender or install an antivirus"
                };
            }
            catch
            {
                return new SecurityCheck
                {
                    Name = "Antivirus Protection",
                    Category = "Security Software",
                    Passed = false,
                    Detail = "No antivirus detected",
                    Recommendation = "Install antivirus software"
                };
            }
        }

        private SecurityCheck CheckFirewall()
        {
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile");
                var enabled = Convert.ToInt32(key?.GetValue("EnableFirewall") ?? 0) == 1;
                return new SecurityCheck
                {
                    Name = "Windows Firewall",
                    Category = "Network Security",
                    Passed = enabled,
                    Detail = enabled ? "Windows Firewall is enabled" : "Windows Firewall is disabled",
                    Recommendation = !enabled ? "Enable Windows Firewall for network protection" : ""
                };
            }
            catch
            {
                return new SecurityCheck
                {
                    Name = "Windows Firewall",
                    Category = "Network Security",
                    Passed = false,
                    Detail = "Could not check firewall status",
                    Recommendation = "Verify Windows Firewall is enabled"
                };
            }
        }

        private SecurityCheck CheckUAC()
        {
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System");
                var enabled = Convert.ToInt32(key?.GetValue("EnableLUA") ?? 0) == 1;
                return new SecurityCheck
                {
                    Name = "User Account Control (UAC)",
                    Category = "Access Control",
                    Passed = enabled,
                    Detail = enabled ? "UAC is enabled" : "UAC is disabled",
                    Recommendation = !enabled ? "Enable UAC to prevent unauthorized changes" : ""
                };
            }
            catch
            {
                return new SecurityCheck { Name = "User Account Control (UAC)", Category = "Access Control",
                    Passed = false, Detail = "Could not check UAC", Recommendation = "Verify UAC is enabled" };
            }
        }

        private SecurityCheck CheckBitLocker()
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(@"root\CIMV2\Security\MicrosoftVolumeEncryption",
                    "SELECT ProtectionStatus FROM Win32_EncryptableVolume WHERE DriveLetter='C:'");
                foreach (ManagementObject obj in searcher.Get())
                {
                    var status = Convert.ToInt32(obj["ProtectionStatus"]);
                    return new SecurityCheck
                    {
                        Name = "Drive Encryption (BitLocker)",
                        Category = "Data Protection",
                        Passed = status == 1,
                        Detail = status == 1 ? "BitLocker is active on C:" : "BitLocker is not active on C:",
                        Recommendation = status != 1 ? "Enable BitLocker to protect your data (requires Windows Pro)" : ""
                    };
                }
            }
            catch { }
            return new SecurityCheck
            {
                Name = "Drive Encryption (BitLocker)",
                Category = "Data Protection",
                Passed = false,
                Detail = "BitLocker not available (may require Windows Pro)",
                Recommendation = "Consider enabling drive encryption"
            };
        }

        private SecurityCheck CheckWindowsVersion()
        {
            var build = Environment.OSVersion.Version.Build;
            var supported = build >= 19041; // Windows 10 2004+
            var name = build >= 22000 ? "Windows 11" : "Windows 10";
            return new SecurityCheck
            {
                Name = "Windows Version",
                Category = "System Updates",
                Passed = supported,
                Detail = $"{name} Build {build}" + (supported ? " (supported)" : " (end of life)"),
                Recommendation = !supported ? "Upgrade to a supported Windows version" : ""
            };
        }

        private SecurityCheck CheckRDP()
        {
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Control\Terminal Server");
                var denied = Convert.ToInt32(key?.GetValue("fDenyTSConnections") ?? 1);
                return new SecurityCheck
                {
                    Name = "Remote Desktop (RDP)",
                    Category = "Network Security",
                    Passed = denied == 1,
                    Detail = denied == 1 ? "RDP is disabled (secure)" : "RDP is enabled - ensure it's needed",
                    Recommendation = denied != 1 ? "Disable RDP if not needed to reduce attack surface" : ""
                };
            }
            catch
            {
                return new SecurityCheck { Name = "Remote Desktop (RDP)", Category = "Network Security",
                    Passed = true, Detail = "Could not check RDP status" };
            }
        }

        private SecurityCheck CheckGuestAccount()
        {
            try
            {
                var psi = new ProcessStartInfo("net", "user Guest")
                {
                    RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true
                };
                using var proc = Process.Start(psi);
                var output = proc!.StandardOutput.ReadToEnd();
                proc.WaitForExit(5000);
                var active = output.Contains("Account active") && output.Contains("Yes");
                return new SecurityCheck
                {
                    Name = "Guest Account",
                    Category = "Access Control",
                    Passed = !active,
                    Detail = !active ? "Guest account is disabled" : "Guest account is enabled",
                    Recommendation = active ? "Disable the Guest account for security" : ""
                };
            }
            catch
            {
                return new SecurityCheck { Name = "Guest Account", Category = "Access Control",
                    Passed = true, Detail = "Could not check Guest account" };
            }
        }

        private SecurityCheck CheckAutoLogin()
        {
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon");
                var username = key?.GetValue("DefaultUserName")?.ToString();
                var password = key?.GetValue("DefaultPassword")?.ToString();
                var autoLogin = !string.IsNullOrEmpty(username) && password != null;
                return new SecurityCheck
                {
                    Name = "Auto-Login",
                    Category = "Access Control",
                    Passed = !autoLogin,
                    Detail = !autoLogin ? "Auto-login is disabled" : $"Auto-login is enabled for {username}",
                    Recommendation = autoLogin ? "Disable auto-login to require password at boot" : ""
                };
            }
            catch
            {
                return new SecurityCheck { Name = "Auto-Login", Category = "Access Control",
                    Passed = true, Detail = "Could not check auto-login" };
            }
        }

        private SecurityCheck CheckSMBv1()
        {
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters");
                var smb1 = key?.GetValue("SMB1");
                var disabled = smb1 != null && Convert.ToInt32(smb1) == 0;
                return new SecurityCheck
                {
                    Name = "SMBv1 Protocol",
                    Category = "Network Security",
                    Passed = disabled || smb1 == null, // null means default (disabled on modern Windows)
                    Detail = disabled || smb1 == null ? "SMBv1 is disabled (secure)" : "SMBv1 is enabled",
                    Recommendation = (!disabled && smb1 != null) ? "Disable SMBv1 to prevent WannaCry-type attacks" : ""
                };
            }
            catch
            {
                return new SecurityCheck { Name = "SMBv1 Protocol", Category = "Network Security",
                    Passed = true, Detail = "Could not check SMBv1 status" };
            }
        }

        private SecurityCheck CheckRealtimeProtection()
        {
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection");
                var disabled = Convert.ToInt32(key?.GetValue("DisableRealtimeMonitoring") ?? 0);
                return new SecurityCheck
                {
                    Name = "Real-Time Protection",
                    Category = "Security Software",
                    Passed = disabled == 0,
                    Detail = disabled == 0 ? "Real-time protection is enabled" : "Real-time protection is disabled",
                    Recommendation = disabled != 0 ? "Enable real-time antimalware protection" : ""
                };
            }
            catch
            {
                return new SecurityCheck { Name = "Real-Time Protection", Category = "Security Software",
                    Passed = true, Detail = "Could not check real-time protection" };
            }
        }

        private SecurityCheck CheckTacticalRmmAgent()
        {
            // Check if Tactical RMM agent service is installed and running
            try
            {
                var sc = new System.ServiceProcess.ServiceController("tacticalrmm");
                var running = sc.Status == System.ServiceProcess.ServiceControllerStatus.Running;
                return new SecurityCheck
                {
                    Name = "Tactical RMM Agent",
                    Category = "RMM Stack",
                    Passed = running,
                    Detail = running ? "Tactical RMM agent is running" : "Tactical RMM agent is not running",
                    Recommendation = !running ? "Contact IT - Tactical RMM agent needs to be installed/started" : ""
                };
            }
            catch
            {
                // Service not found - check alternative service names
                foreach (var svcName in new[] { "TacticalAgent", "tacticalagent", "tabormmSvc", "TacticalRMM" })
                {
                    try
                    {
                        var sc = new System.ServiceProcess.ServiceController(svcName);
                        var running = sc.Status == System.ServiceProcess.ServiceControllerStatus.Running;
                        return new SecurityCheck
                        {
                            Name = "Tactical RMM Agent",
                            Category = "RMM Stack",
                            Passed = running,
                            Detail = running ? $"Tactical RMM agent ({svcName}) is running" : $"Tactical RMM agent ({svcName}) is not running",
                            Recommendation = !running ? "Contact IT - Tactical RMM agent needs to be started" : ""
                        };
                    }
                    catch { continue; }
                }

                // Also check for the executable
                var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
                var trmmPaths = new[]
                {
                    Path.Combine(programFiles, "TacticalAgent", "tacticalrmm.exe"),
                    Path.Combine(programFiles, "Tactical RMM Agent", "tacticalrmm.exe"),
                    @"C:\Program Files\TacticalAgent\tacticalrmm.exe"
                };

                foreach (var path in trmmPaths)
                {
                    if (File.Exists(path))
                    {
                        return new SecurityCheck
                        {
                            Name = "Tactical RMM Agent",
                            Category = "RMM Stack",
                            Passed = false,
                            Detail = "Tactical RMM agent is installed but service is not running",
                            Recommendation = "Start the Tactical RMM agent service"
                        };
                    }
                }

                return new SecurityCheck
                {
                    Name = "Tactical RMM Agent",
                    Category = "RMM Stack",
                    Passed = false,
                    Detail = "Tactical RMM agent is not installed",
                    Recommendation = "Install Tactical RMM agent for remote management and monitoring"
                };
            }
        }

        private SecurityCheck CheckWazuhAgent()
        {
            // Check if Wazuh agent service is installed and running
            try
            {
                var sc = new System.ServiceProcess.ServiceController("WazuhSvc");
                var running = sc.Status == System.ServiceProcess.ServiceControllerStatus.Running;
                return new SecurityCheck
                {
                    Name = "Wazuh Security Agent",
                    Category = "RMM Stack",
                    Passed = running,
                    Detail = running ? "Wazuh SIEM agent is running - intrusion detection active" : "Wazuh SIEM agent is not running",
                    Recommendation = !running ? "Contact IT - Wazuh agent needs to be started for SIEM coverage" : ""
                };
            }
            catch
            {
                // Check alternative service names
                foreach (var svcName in new[] { "Wazuh", "wazuh-agent", "OssecSvc" })
                {
                    try
                    {
                        var sc = new System.ServiceProcess.ServiceController(svcName);
                        var running = sc.Status == System.ServiceProcess.ServiceControllerStatus.Running;
                        return new SecurityCheck
                        {
                            Name = "Wazuh Security Agent",
                            Category = "RMM Stack",
                            Passed = running,
                            Detail = running ? $"Wazuh SIEM agent ({svcName}) is running" : $"Wazuh agent ({svcName}) is not running",
                            Recommendation = !running ? "Contact IT - Wazuh agent needs to be started" : ""
                        };
                    }
                    catch { continue; }
                }

                // Check for Wazuh installation path
                var wazuhPaths = new[]
                {
                    @"C:\Program Files (x86)\ossec-agent\wazuh-agent.exe",
                    @"C:\Program Files\ossec-agent\wazuh-agent.exe",
                    @"C:\Program Files (x86)\ossec-agent\ossec-agent.exe"
                };

                foreach (var path in wazuhPaths)
                {
                    if (File.Exists(path))
                    {
                        return new SecurityCheck
                        {
                            Name = "Wazuh Security Agent",
                            Category = "RMM Stack",
                            Passed = false,
                            Detail = "Wazuh agent is installed but service is not running",
                            Recommendation = "Start the Wazuh agent service for SIEM coverage"
                        };
                    }
                }

                return new SecurityCheck
                {
                    Name = "Wazuh Security Agent",
                    Category = "RMM Stack",
                    Passed = false,
                    Detail = "Wazuh SIEM agent is not installed",
                    Recommendation = "Install Wazuh agent for intrusion detection and security monitoring"
                };
            }
        }

        #endregion

        #region Fix My Computer

        public async Task<string> RunFixMyComputerAsync()
        {
            var results = new List<string>();

            // 1. Clear temp files
            await RunCommandAsync("cmd.exe", "/c del /q /f /s %TEMP%\\* 2>nul", "Clearing temp files...", results);

            // 2. Flush DNS
            await RunCommandAsync("ipconfig", "/flushdns", "Flushing DNS cache...", results);

            // 3. Reset Winsock
            await RunCommandAsync("netsh", "winsock reset", "Resetting Winsock catalog...", results);

            // 4. Clear Windows icon cache
            await RunCommandAsync("cmd.exe", "/c ie4uinit.exe -show", "Refreshing icons...", results);

            // 5. Clear ARP cache
            await RunCommandAsync("netsh", "interface ip delete arpcache", "Clearing ARP cache...", results);

            // 6. Restart Explorer to refresh desktop
            try
            {
                foreach (var explorer in Process.GetProcessesByName("explorer"))
                {
                    explorer.Kill();
                    explorer.WaitForExit(3000);
                }
                Process.Start("explorer.exe");
                results.Add("Refreshed Windows Explorer");
            }
            catch { results.Add("Could not restart Explorer"); }

            return string.Join("\n", results);
        }

        private async Task RunCommandAsync(string exe, string args, string label, List<string> results)
        {
            try
            {
                var psi = new ProcessStartInfo(exe, args)
                {
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using var proc = Process.Start(psi);
                if (proc != null)
                {
                    await proc.WaitForExitAsync();
                    results.Add($"{label} Done.");
                }
            }
            catch (Exception ex)
            {
                results.Add($"{label} Error: {ex.Message}");
            }
        }

        #endregion

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            _pollTimer?.Dispose();
            _cpuCounter?.Dispose();
        }
    }
}
