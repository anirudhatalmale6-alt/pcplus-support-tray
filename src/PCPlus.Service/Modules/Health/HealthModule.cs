using System.Diagnostics;
using System.Management;
using System.Net.NetworkInformation;
using System.Text.Json;
using LibreHardwareMonitor.Hardware;
using PCPlus.Core.Interfaces;
using PCPlus.Core.Models;

namespace PCPlus.Service.Modules.Health
{
    /// <summary>
    /// Health monitoring module. Polls CPU, RAM, disk, temps, network, processes.
    /// Fires alerts on threshold breaches. Maintains history for sparklines.
    /// Free tier - always available.
    /// </summary>
    public class HealthModule : IModule
    {
        public string Id => "health";
        public string Name => "System Health Monitor";
        public string Version => "4.0.0";
        public LicenseTier RequiredTier => LicenseTier.Free;
        public bool IsRunning { get; private set; }

        private IModuleContext _context = null!;
        private Timer? _pollTimer;
        private PerformanceCounter? _cpuCounter;
        private readonly Queue<HealthSnapshot> _history = new();
        private HealthSnapshot _current = new();
        private readonly object _lock = new();

        // Network tracking
        private long _lastBytesSent;
        private long _lastBytesRecv;
        private DateTime _lastNetworkCheck = DateTime.MinValue;

        // Alert cooldown
        private readonly Dictionary<string, DateTime> _alertCooldowns = new();
        private const int COOLDOWN_SECONDS = 300;

        private const int MAX_HISTORY = 300; // 5 minutes at 1s intervals

        public Task InitializeAsync(IModuleContext context)
        {
            _context = context;
            try
            {
                _cpuCounter = new PerformanceCounter("Processor", "% Processor Time", "_Total");
                _cpuCounter.NextValue();
            }
            catch { _cpuCounter = null; }
            return Task.CompletedTask;
        }

        public Task StartAsync(CancellationToken cancellationToken)
        {
            var interval = _context.Config.HealthPollIntervalMs;
            _pollTimer = new Timer(Poll, null, 0, interval);
            IsRunning = true;
            return Task.CompletedTask;
        }

        public Task StopAsync()
        {
            _pollTimer?.Change(Timeout.Infinite, Timeout.Infinite);
            _pollTimer?.Dispose();
            _pollTimer = null;
            _cpuCounter?.Dispose();
            _computer?.Close();
            _computer = null;
            IsRunning = false;
            return Task.CompletedTask;
        }

        public Task<ModuleResponse> HandleCommandAsync(ModuleCommand command)
        {
            return Task.FromResult(command.Action switch
            {
                "GetHealthSnapshot" => ModuleResponse.Ok("", new Dictionary<string, object>
                {
                    ["snapshot"] = _current
                }),
                "GetHealthHistory" => ModuleResponse.Ok("", new Dictionary<string, object>
                {
                    ["history"] = GetHistory()
                }),
                _ => ModuleResponse.Fail($"Unknown action: {command.Action}")
            });
        }

        public ModuleStatus GetStatus() => new()
        {
            ModuleId = Id,
            ModuleName = Name,
            IsRunning = IsRunning,
            RequiredTier = RequiredTier,
            StatusText = IsRunning ? $"Monitoring (CPU: {_current.CpuPercent:F0}%)" : "Stopped",
            LastActivity = _current.Timestamp,
            Metrics = new()
            {
                ["cpuPercent"] = _current.CpuPercent,
                ["ramPercent"] = _current.RamPercent,
                ["cpuTempC"] = _current.CpuTempC,
                ["gpuTempC"] = _current.GpuTempC,
                ["processCount"] = _current.ProcessCount
            }
        };

        private void Poll(object? state)
        {
            try
            {
                var snapshot = new HealthSnapshot { Timestamp = DateTime.UtcNow };

                // CPU
                try
                {
                    snapshot.CpuPercent = _cpuCounter?.NextValue() ?? GetCpuViaWmi();
                }
                catch { snapshot.CpuPercent = GetCpuViaWmi(); }

                // RAM
                PollRam(snapshot);

                // Disks
                PollDisks(snapshot);

                // Temperatures
                PollTemps(snapshot);

                // Network
                PollNetwork(snapshot);

                // Processes
                PollProcesses(snapshot);

                // Uptime
                snapshot.Uptime = TimeSpan.FromMilliseconds(Environment.TickCount64);

                lock (_lock)
                {
                    _current = snapshot;
                    _history.Enqueue(snapshot);
                    while (_history.Count > MAX_HISTORY) _history.Dequeue();
                }

                // Check thresholds and raise alerts
                CheckAlerts(snapshot);
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

        private Computer? _computer;

        private void PollTemps(HealthSnapshot snap)
        {
            // Primary: LibreHardwareMonitorLib (direct hardware access, no external tool needed)
            if (TryLibreHardwareMonitor(snap)) return;
            // Fallback: WMI queries for external LHM/OHM instances
            if (TryWmiTemps(snap, "root\\LibreHardwareMonitor")) return;
            if (TryWmiTemps(snap, "root\\OpenHardwareMonitor")) return;
            TryAcpiTemp(snap);
        }

        private bool TryLibreHardwareMonitor(HealthSnapshot snap)
        {
            try
            {
                if (_computer == null)
                {
                    _computer = new Computer
                    {
                        IsCpuEnabled = true,
                        IsGpuEnabled = true,
                        IsMotherboardEnabled = true
                    };
                    _computer.Open();
                }

                bool found = false;
                foreach (var hardware in _computer.Hardware)
                {
                    hardware.Update();
                    foreach (var subHardware in hardware.SubHardware)
                        subHardware.Update();

                    foreach (var sensor in hardware.Sensors)
                    {
                        if (sensor.SensorType != SensorType.Temperature || !sensor.Value.HasValue)
                            continue;

                        var val = sensor.Value.Value;
                        if (val <= 0 || val > 120) continue;

                        if (snap.CpuTempC == 0 && (hardware.HardwareType == HardwareType.Cpu))
                        {
                            snap.CpuTempC = val;
                            snap.CpuTempSource = $"{hardware.Name} - {sensor.Name}";
                            found = true;
                        }

                        if (snap.GpuTempC == 0 && (hardware.HardwareType == HardwareType.GpuNvidia ||
                            hardware.HardwareType == HardwareType.GpuAmd || hardware.HardwareType == HardwareType.GpuIntel))
                        {
                            snap.GpuTempC = val;
                            snap.GpuTempSource = $"{hardware.Name} - {sensor.Name}";
                            found = true;
                        }
                    }

                    foreach (var sub in hardware.SubHardware)
                    {
                        foreach (var sensor in sub.Sensors)
                        {
                            if (sensor.SensorType != SensorType.Temperature || !sensor.Value.HasValue)
                                continue;

                            var val = sensor.Value.Value;
                            if (val <= 0 || val > 120) continue;

                            if (snap.CpuTempC == 0 && sensor.Name.Contains("Core", StringComparison.OrdinalIgnoreCase))
                            {
                                snap.CpuTempC = val;
                                snap.CpuTempSource = $"{sub.Name} - {sensor.Name}";
                                found = true;
                            }
                        }
                    }
                }
                return found;
            }
            catch
            {
                _computer?.Close();
                _computer = null;
                return false;
            }
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

        private void CheckAlerts(HealthSnapshot snap)
        {
            var cfg = _context.Config;
            if (snap.CpuPercent > cfg.CpuAlertThreshold)
                RaiseThrottled("cpu_high", "High CPU Usage", $"CPU at {snap.CpuPercent:F0}%", AlertSeverity.Warning);
            if (snap.RamPercent > cfg.RamAlertThreshold)
                RaiseThrottled("ram_high", "High Memory Usage", $"RAM at {snap.RamPercent:F0}%", AlertSeverity.Warning);
            if (snap.CpuTempC > cfg.TempAlertThreshold && snap.CpuTempC > 0)
                RaiseThrottled("cpu_temp", "CPU Temperature Critical", $"CPU at {snap.CpuTempC:F0}C", AlertSeverity.Critical);
            if (snap.GpuTempC > cfg.TempAlertThreshold && snap.GpuTempC > 0)
                RaiseThrottled("gpu_temp", "GPU Temperature Critical", $"GPU at {snap.GpuTempC:F0}C", AlertSeverity.Critical);

            foreach (var disk in snap.Disks)
            {
                if (disk.UsedPercent > cfg.DiskAlertThreshold)
                    RaiseThrottled($"disk_{disk.Name}", "Low Disk Space",
                        $"Drive {disk.Name} at {disk.UsedPercent:F0}% ({disk.FreeGB:F1} GB free)", AlertSeverity.Warning);
            }
        }

        private void RaiseThrottled(string key, string title, string message, AlertSeverity severity)
        {
            lock (_alertCooldowns)
            {
                if (_alertCooldowns.TryGetValue(key, out var last) &&
                    (DateTime.UtcNow - last).TotalSeconds < COOLDOWN_SECONDS)
                    return;
                _alertCooldowns[key] = DateTime.UtcNow;
            }

            _context.RaiseAlert(new Alert
            {
                ModuleId = Id,
                Title = title,
                Message = message,
                Severity = severity,
                Category = "health"
            });
        }

        private List<HealthSnapshot> GetHistory()
        {
            lock (_lock) { return new List<HealthSnapshot>(_history); }
        }
    }
}
