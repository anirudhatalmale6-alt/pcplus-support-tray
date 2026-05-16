using System.Management;
using PCPlus.Core.Interfaces;
using PCPlus.Core.Models;

namespace PCPlus.Service.Modules.Security
{
    public class UsbDeviceMonitor : IDisposable
    {
        private const string ModuleName = "usb-monitor";
        private IModuleContext _context = null!;
        private ManagementEventWatcher? _insertWatcher;
        private ManagementEventWatcher? _removeWatcher;
        private readonly List<UsbEvent> _events = new();
        private readonly HashSet<string> _knownDevices = new(StringComparer.OrdinalIgnoreCase);
        private int _insertCount;
        private int _blockedCount;

        public void Start(IModuleContext context)
        {
            _context = context;
            CaptureExistingDevices();
            StartWatching();
            _context.Log(LogLevel.Info, ModuleName,
                $"USB device monitor active ({_knownDevices.Count} existing devices)");
        }

        public void Dispose()
        {
            try { _insertWatcher?.Stop(); } catch { }
            try { _removeWatcher?.Stop(); } catch { }
            _insertWatcher?.Dispose();
            _removeWatcher?.Dispose();
        }

        public (int inserted, int blocked) GetStats() => (_insertCount, _blockedCount);

        private void CaptureExistingDevices()
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    "SELECT * FROM Win32_USBHub");
                foreach (ManagementObject obj in searcher.Get())
                {
                    var deviceId = obj["DeviceID"]?.ToString() ?? "";
                    if (!string.IsNullOrEmpty(deviceId))
                        _knownDevices.Add(deviceId);
                    obj.Dispose();
                }
            }
            catch { }
        }

        private void StartWatching()
        {
            try
            {
                // Watch for USB device insertion
                var insertQuery = new WqlEventQuery(
                    "SELECT * FROM __InstanceCreationEvent WITHIN 2 " +
                    "WHERE TargetInstance ISA 'Win32_USBHub'");
                _insertWatcher = new ManagementEventWatcher(insertQuery);
                _insertWatcher.EventArrived += OnDeviceInserted;
                _insertWatcher.Start();

                // Watch for USB device removal
                var removeQuery = new WqlEventQuery(
                    "SELECT * FROM __InstanceDeletionEvent WITHIN 2 " +
                    "WHERE TargetInstance ISA 'Win32_USBHub'");
                _removeWatcher = new ManagementEventWatcher(removeQuery);
                _removeWatcher.EventArrived += OnDeviceRemoved;
                _removeWatcher.Start();
            }
            catch (Exception ex)
            {
                _context.Log(LogLevel.Warning, ModuleName,
                    $"USB WMI watcher failed: {ex.Message}");
            }
        }

        private void OnDeviceInserted(object sender, EventArrivedEventArgs e)
        {
            try
            {
                var target = (ManagementBaseObject)e.NewEvent["TargetInstance"];
                var deviceId = target["DeviceID"]?.ToString() ?? "Unknown";
                var name = target["Name"]?.ToString() ?? "Unknown USB Device";
                var description = target["Description"]?.ToString() ?? "";

                _insertCount++;
                bool isNew = _knownDevices.Add(deviceId);

                var evt = new UsbEvent
                {
                    DeviceId = deviceId,
                    DeviceName = name,
                    Action = "Inserted",
                    IsNewDevice = isNew,
                    Timestamp = DateTime.UtcNow
                };
                _events.Add(evt);
                if (_events.Count > 500) _events.RemoveRange(0, 250);

                var severity = isNew ? AlertSeverity.Warning : AlertSeverity.Info;
                var title = isNew ? "New USB Device Connected" : "Known USB Device Connected";

                _context.RaiseAlert(new Alert
                {
                    ModuleId = ModuleName,
                    Title = title,
                    Message = $"{name} ({deviceId})",
                    Severity = severity,
                    Category = "usb",
                    Metadata = new()
                    {
                        ["deviceId"] = deviceId,
                        ["deviceName"] = name,
                        ["isNew"] = isNew.ToString()
                    }
                });

                if (isNew)
                {
                    _context.Log(LogLevel.Warning, ModuleName,
                        $"NEW USB device: {name} ({deviceId})");

                    // Check if USB blocking is enabled
                    if (_context.Config.BlockUSB)
                    {
                        _blockedCount++;
                        _context.Log(LogLevel.Warning, ModuleName,
                            $"USB blocking active - device {name} may be restricted by policy");
                    }
                }
                else
                {
                    _context.Log(LogLevel.Info, ModuleName,
                        $"Known USB device reconnected: {name}");
                }
            }
            catch { }
        }

        private void OnDeviceRemoved(object sender, EventArrivedEventArgs e)
        {
            try
            {
                var target = (ManagementBaseObject)e.NewEvent["TargetInstance"];
                var deviceId = target["DeviceID"]?.ToString() ?? "Unknown";
                var name = target["Name"]?.ToString() ?? "Unknown USB Device";

                _events.Add(new UsbEvent
                {
                    DeviceId = deviceId,
                    DeviceName = name,
                    Action = "Removed",
                    Timestamp = DateTime.UtcNow
                });

                _context.Log(LogLevel.Info, ModuleName, $"USB device removed: {name}");
            }
            catch { }
        }
    }

    public class UsbEvent
    {
        public string DeviceId { get; set; } = "";
        public string DeviceName { get; set; } = "";
        public string Action { get; set; } = "";
        public bool IsNewDevice { get; set; }
        public DateTime Timestamp { get; set; }
    }
}
