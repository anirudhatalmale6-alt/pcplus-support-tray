using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;

namespace SupportTray
{
    /// <summary>
    /// Real-time system health monitoring engine.
    /// Polls CPU, RAM, disk, temperatures, and network at configurable intervals.
    /// Fires events when thresholds are exceeded.
    /// </summary>
    public class HealthMonitor : IDisposable
    {
        private System.Threading.Timer? _pollTimer;
        private readonly object _lock = new();
        private bool _disposed;

        // Current readings
        public float CpuPercent { get; private set; }
        public float RamPercent { get; private set; }
        public float RamUsedGB { get; private set; }
        public float RamTotalGB { get; private set; }
        public List<DiskReading> Disks { get; private set; } = new();
        public float CpuTempC { get; private set; }
        public float GpuTempC { get; private set; }
        public string CpuTempSource { get; private set; } = "";
        public string GpuTempSource { get; private set; } = "";
        public float NetworkSentKBps { get; private set; }
        public float NetworkRecvKBps { get; private set; }
        public TimeSpan Uptime { get; private set; }
        public int ProcessCount { get; private set; }
        public int TopCpuProcessCount { get; private set; } = 5;
        public List<ProcessReading> TopProcesses { get; private set; } = new();
        public DateTime LastUpdate { get; private set; }

        // Network tracking
        private long _lastBytesSent;
        private long _lastBytesRecv;
        private DateTime _lastNetworkCheck = DateTime.MinValue;

        // CPU tracking via WMI (more reliable than PerformanceCounter on some systems)
        private PerformanceCounter? _cpuCounter;

        // Events
        public event Action<HealthSnapshot>? OnUpdate;
        public event Action<HealthAlert>? OnAlert;

        // Thresholds
        public float CpuAlertThreshold { get; set; } = 90f;
        public float RamAlertThreshold { get; set; } = 90f;
        public float DiskAlertThreshold { get; set; } = 90f;
        public float TempAlertThreshold { get; set; } = 85f;
        public int PollIntervalMs { get; set; } = 2000;

        // Alert cooldown tracking (don't spam alerts)
        private readonly Dictionary<string, DateTime> _alertCooldowns = new();
        private const int ALERT_COOLDOWN_SECONDS = 300; // 5 minutes between same alert

        public HealthMonitor()
        {
            try
            {
                _cpuCounter = new PerformanceCounter("Processor", "% Processor Time", "_Total");
                _cpuCounter.NextValue(); // First call always returns 0
            }
            catch
            {
                _cpuCounter = null;
            }
        }

        public void Start()
        {
            if (_pollTimer != null) return;
            _pollTimer = new System.Threading.Timer(PollCallback, null, 0, PollIntervalMs);
        }

        public void Stop()
        {
            _pollTimer?.Change(Timeout.Infinite, Timeout.Infinite);
            _pollTimer?.Dispose();
            _pollTimer = null;
        }

        private void PollCallback(object? state)
        {
            try
            {
                lock (_lock)
                {
                    PollCpu();
                    PollRam();
                    PollDisks();
                    PollTemperatures();
                    PollNetwork();
                    PollProcesses();
                    Uptime = TimeSpan.FromMilliseconds(Environment.TickCount64);
                    LastUpdate = DateTime.Now;
                }

                var snapshot = GetSnapshot();
                OnUpdate?.Invoke(snapshot);
                CheckAlerts(snapshot);
            }
            catch { }
        }

        private void PollCpu()
        {
            try
            {
                if (_cpuCounter != null)
                {
                    CpuPercent = _cpuCounter.NextValue();
                }
                else
                {
                    // Fallback: WMI
                    using var searcher = new ManagementObjectSearcher(
                        "SELECT LoadPercentage FROM Win32_Processor");
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        CpuPercent = Convert.ToSingle(obj["LoadPercentage"]);
                        break;
                    }
                }
            }
            catch { }
        }

        private void PollRam()
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    "SELECT TotalVisibleMemorySize, FreePhysicalMemory FROM Win32_OperatingSystem");
                foreach (ManagementObject obj in searcher.Get())
                {
                    var totalKB = Convert.ToDouble(obj["TotalVisibleMemorySize"]);
                    var freeKB = Convert.ToDouble(obj["FreePhysicalMemory"]);
                    RamTotalGB = (float)(totalKB / 1024.0 / 1024.0);
                    RamUsedGB = (float)((totalKB - freeKB) / 1024.0 / 1024.0);
                    RamPercent = (float)((totalKB - freeKB) / totalKB * 100.0);
                    break;
                }
            }
            catch { }
        }

        private void PollDisks()
        {
            try
            {
                var disks = new List<DiskReading>();
                foreach (var drive in DriveInfo.GetDrives())
                {
                    if (drive.IsReady && drive.DriveType == DriveType.Fixed)
                    {
                        var totalGB = drive.TotalSize / (1024.0 * 1024 * 1024);
                        var freeGB = drive.AvailableFreeSpace / (1024.0 * 1024 * 1024);
                        var usedPct = ((totalGB - freeGB) / totalGB) * 100;
                        disks.Add(new DiskReading
                        {
                            Name = drive.Name.TrimEnd('\\'),
                            Label = drive.VolumeLabel,
                            TotalGB = (float)totalGB,
                            FreeGB = (float)freeGB,
                            UsedPercent = (float)usedPct
                        });
                    }
                }
                Disks = disks;
            }
            catch { }
        }

        private void PollTemperatures()
        {
            // Try Open Hardware Monitor / LibreHardwareMonitor WMI namespace first
            // These are available when LibreHardwareMonitor or OpenHardwareMonitor is running
            // as a service or when our app uses the library directly
            try
            {
                // Try LibreHardwareMonitor WMI (if running as service)
                bool found = TryWmiTemps("root\\LibreHardwareMonitor",
                    "SELECT Value, Name, SensorType, Parent FROM Sensor WHERE SensorType='Temperature'");
                if (!found)
                {
                    // Try OpenHardwareMonitor WMI
                    found = TryWmiTemps("root\\OpenHardwareMonitor",
                        "SELECT Value, Name, SensorType, Parent FROM Sensor WHERE SensorType='Temperature'");
                }
                if (!found)
                {
                    // Fallback: MSAcpi_ThermalZoneTemperature (built-in, requires admin)
                    TryMsAcpiTemp();
                }
            }
            catch { }
        }

        private bool TryWmiTemps(string wmiNamespace, string query)
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(wmiNamespace, query);
                var results = searcher.Get();
                bool foundCpu = false, foundGpu = false;

                foreach (ManagementObject obj in results)
                {
                    var name = obj["Name"]?.ToString() ?? "";
                    var parent = obj["Parent"]?.ToString() ?? "";
                    var value = Convert.ToSingle(obj["Value"]);

                    // CPU temperature
                    if (!foundCpu && (name.Contains("CPU", StringComparison.OrdinalIgnoreCase) ||
                        name.Contains("Core", StringComparison.OrdinalIgnoreCase) ||
                        parent.Contains("cpu", StringComparison.OrdinalIgnoreCase)))
                    {
                        // Take the package temp or first core temp
                        if (name.Contains("Package", StringComparison.OrdinalIgnoreCase) ||
                            name.Contains("CPU", StringComparison.OrdinalIgnoreCase) ||
                            !foundCpu)
                        {
                            CpuTempC = value;
                            CpuTempSource = name;
                            foundCpu = true;
                        }
                    }

                    // GPU temperature
                    if (!foundGpu && (name.Contains("GPU", StringComparison.OrdinalIgnoreCase) ||
                        parent.Contains("gpu", StringComparison.OrdinalIgnoreCase) ||
                        parent.Contains("nvidia", StringComparison.OrdinalIgnoreCase) ||
                        parent.Contains("amd", StringComparison.OrdinalIgnoreCase)))
                    {
                        GpuTempC = value;
                        GpuTempSource = name;
                        foundGpu = true;
                    }
                }

                return foundCpu || foundGpu;
            }
            catch { return false; }
        }

        private void TryMsAcpiTemp()
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    "root\\WMI",
                    "SELECT CurrentTemperature FROM MSAcpi_ThermalZoneTemperature");
                foreach (ManagementObject obj in searcher.Get())
                {
                    // Value is in tenths of Kelvin
                    var tempK = Convert.ToDouble(obj["CurrentTemperature"]) / 10.0;
                    var tempC = (float)(tempK - 273.15);
                    if (tempC > 0 && tempC < 120)
                    {
                        CpuTempC = tempC;
                        CpuTempSource = "ACPI Thermal Zone";
                    }
                    break;
                }
            }
            catch { }
        }

        private void PollNetwork()
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

                var now = DateTime.Now;
                if (_lastNetworkCheck != DateTime.MinValue)
                {
                    var elapsed = (now - _lastNetworkCheck).TotalSeconds;
                    if (elapsed > 0)
                    {
                        NetworkSentKBps = (float)((totalSent - _lastBytesSent) / 1024.0 / elapsed);
                        NetworkRecvKBps = (float)((totalRecv - _lastBytesRecv) / 1024.0 / elapsed);
                    }
                }

                _lastBytesSent = totalSent;
                _lastBytesRecv = totalRecv;
                _lastNetworkCheck = now;
            }
            catch { }
        }

        private void PollProcesses()
        {
            try
            {
                var processes = Process.GetProcesses();
                ProcessCount = processes.Length;

                // Get top processes by working set (memory) - CPU per-process is expensive
                var top = processes
                    .Where(p => { try { return p.WorkingSet64 > 0 && !string.IsNullOrEmpty(p.ProcessName); } catch { return false; } })
                    .OrderByDescending(p => { try { return p.WorkingSet64; } catch { return 0L; } })
                    .Take(TopCpuProcessCount)
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
                    .ToList();

                TopProcesses = top!;

                foreach (var p in processes)
                {
                    try { p.Dispose(); } catch { }
                }
            }
            catch { }
        }

        private void CheckAlerts(HealthSnapshot snapshot)
        {
            if (snapshot.CpuPercent > CpuAlertThreshold)
                RaiseAlert("CPU", $"CPU usage at {snapshot.CpuPercent:F0}%", AlertSeverity.Warning);

            if (snapshot.RamPercent > RamAlertThreshold)
                RaiseAlert("RAM", $"Memory usage at {snapshot.RamPercent:F0}%", AlertSeverity.Warning);

            if (snapshot.CpuTempC > TempAlertThreshold && snapshot.CpuTempC > 0)
                RaiseAlert("CPU_TEMP", $"CPU temperature at {snapshot.CpuTempC:F0} C", AlertSeverity.Critical);

            if (snapshot.GpuTempC > TempAlertThreshold && snapshot.GpuTempC > 0)
                RaiseAlert("GPU_TEMP", $"GPU temperature at {snapshot.GpuTempC:F0} C", AlertSeverity.Critical);

            foreach (var disk in snapshot.Disks)
            {
                if (disk.UsedPercent > DiskAlertThreshold)
                    RaiseAlert($"DISK_{disk.Name}", $"Disk {disk.Name} at {disk.UsedPercent:F0}% full", AlertSeverity.Warning);
            }
        }

        private void RaiseAlert(string key, string message, AlertSeverity severity)
        {
            lock (_alertCooldowns)
            {
                if (_alertCooldowns.TryGetValue(key, out var lastAlert) &&
                    (DateTime.Now - lastAlert).TotalSeconds < ALERT_COOLDOWN_SECONDS)
                    return;

                _alertCooldowns[key] = DateTime.Now;
            }

            OnAlert?.Invoke(new HealthAlert
            {
                Key = key,
                Message = message,
                Severity = severity,
                Timestamp = DateTime.Now
            });
        }

        public HealthSnapshot GetSnapshot()
        {
            lock (_lock)
            {
                return new HealthSnapshot
                {
                    CpuPercent = CpuPercent,
                    RamPercent = RamPercent,
                    RamUsedGB = RamUsedGB,
                    RamTotalGB = RamTotalGB,
                    Disks = new List<DiskReading>(Disks),
                    CpuTempC = CpuTempC,
                    GpuTempC = GpuTempC,
                    CpuTempSource = CpuTempSource,
                    GpuTempSource = GpuTempSource,
                    NetworkSentKBps = NetworkSentKBps,
                    NetworkRecvKBps = NetworkRecvKBps,
                    Uptime = Uptime,
                    ProcessCount = ProcessCount,
                    TopProcesses = new List<ProcessReading>(TopProcesses),
                    Timestamp = LastUpdate
                };
            }
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            Stop();
            _cpuCounter?.Dispose();
        }
    }

    public class HealthSnapshot
    {
        public float CpuPercent { get; set; }
        public float RamPercent { get; set; }
        public float RamUsedGB { get; set; }
        public float RamTotalGB { get; set; }
        public List<DiskReading> Disks { get; set; } = new();
        public float CpuTempC { get; set; }
        public float GpuTempC { get; set; }
        public string CpuTempSource { get; set; } = "";
        public string GpuTempSource { get; set; } = "";
        public float NetworkSentKBps { get; set; }
        public float NetworkRecvKBps { get; set; }
        public TimeSpan Uptime { get; set; }
        public int ProcessCount { get; set; }
        public List<ProcessReading> TopProcesses { get; set; } = new();
        public DateTime Timestamp { get; set; }
    }

    public class DiskReading
    {
        public string Name { get; set; } = "";
        public string Label { get; set; } = "";
        public float TotalGB { get; set; }
        public float FreeGB { get; set; }
        public float UsedPercent { get; set; }
    }

    public class ProcessReading
    {
        public string Name { get; set; } = "";
        public float MemoryMB { get; set; }
        public int Pid { get; set; }
    }

    public class HealthAlert
    {
        public string Key { get; set; } = "";
        public string Message { get; set; } = "";
        public AlertSeverity Severity { get; set; }
        public DateTime Timestamp { get; set; }
    }

    public enum AlertSeverity
    {
        Info,
        Warning,
        Critical
    }
}
