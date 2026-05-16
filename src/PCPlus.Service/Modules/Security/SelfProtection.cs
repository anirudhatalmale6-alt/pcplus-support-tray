using System.Diagnostics;
using System.Management;
using System.Security.Cryptography;
using System.ServiceProcess;
using Microsoft.Win32;
using PCPlus.Core.Interfaces;
using PCPlus.Core.Models;

namespace PCPlus.Service.Modules.Security
{
    public class SelfProtection : IDisposable
    {
        private const string ModuleName = "self-protection";
        private static readonly string DataDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "PCPlusEndpoint");

        private readonly IModuleContext _context;
        private Timer? _serviceWatchdog;
        private Timer? _integrityTimer;
        private ManagementEventWatcher? _processWatcher;
        private readonly Dictionary<string, string> _binaryHashes = new();

        private static readonly string[] ProtectedServices = new[]
        {
            "PCPlusEndpoint",
            "WazuhSvc",
            "WinDefend",
            "VSS"
        };

        private static readonly string[] ProtectedProcesses = new[]
        {
            "PCPlusService",
            "PCPlusTray"
        };

        public SelfProtection(IModuleContext context)
        {
            _context = context;
        }

        public void Start()
        {
            CaptureBinaryBaseline();
            StartServiceWatchdog();
            StartProcessProtection();
            ProtectInstallation();
            _context.Log(LogLevel.Info, ModuleName, "Self-protection active");
        }

        public void Dispose()
        {
            _serviceWatchdog?.Dispose();
            _integrityTimer?.Dispose();
            try { _processWatcher?.Stop(); } catch { }
            _processWatcher?.Dispose();
        }

        private void CaptureBinaryBaseline()
        {
            try
            {
                var serviceDir = AppContext.BaseDirectory;
                foreach (var file in Directory.GetFiles(serviceDir, "*.exe")
                    .Concat(Directory.GetFiles(serviceDir, "*.dll")))
                {
                    try
                    {
                        using var stream = File.OpenRead(file);
                        var hash = Convert.ToHexString(SHA256.HashData(stream));
                        _binaryHashes[file] = hash;
                    }
                    catch { }
                }

                _integrityTimer = new Timer(_ => VerifyBinaryIntegrity(), null,
                    TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(10));

                _context.Log(LogLevel.Info, ModuleName,
                    $"Binary integrity baseline: {_binaryHashes.Count} files tracked");
            }
            catch (Exception ex)
            {
                _context.Log(LogLevel.Warning, ModuleName,
                    $"Failed to capture binary baseline: {ex.Message}");
            }
        }

        private void VerifyBinaryIntegrity()
        {
            try
            {
                foreach (var (file, expectedHash) in _binaryHashes)
                {
                    if (!File.Exists(file))
                    {
                        _context.RaiseAlert(new Alert
                        {
                            ModuleId = ModuleName,
                            Title = "Binary Tampering Detected",
                            Message = $"Protected file deleted: {Path.GetFileName(file)}",
                            Severity = AlertSeverity.Critical,
                            Timestamp = DateTime.UtcNow
                        });
                        continue;
                    }

                    using var stream = File.OpenRead(file);
                    var currentHash = Convert.ToHexString(SHA256.HashData(stream));
                    if (!currentHash.Equals(expectedHash, StringComparison.OrdinalIgnoreCase))
                    {
                        _context.RaiseAlert(new Alert
                        {
                            ModuleId = ModuleName,
                            Title = "Binary Tampering Detected",
                            Message = $"File modified: {Path.GetFileName(file)}",
                            Severity = AlertSeverity.Critical,
                            Timestamp = DateTime.UtcNow
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                _context.Log(LogLevel.Warning, ModuleName, $"Integrity check failed: {ex.Message}");
            }
        }

        private void StartServiceWatchdog()
        {
            _serviceWatchdog = new Timer(_ => CheckProtectedServices(), null,
                TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30));
        }

        private void CheckProtectedServices()
        {
            foreach (var svcName in ProtectedServices)
            {
                try
                {
                    using var sc = new ServiceController(svcName);
                    if (sc.Status != ServiceControllerStatus.Running &&
                        sc.Status != ServiceControllerStatus.StartPending)
                    {
                        if (svcName == "PCPlusEndpoint") continue; // don't restart ourselves

                        _context.Log(LogLevel.Warning, ModuleName,
                            $"Protected service {svcName} is {sc.Status}. Restarting...");

                        try
                        {
                            sc.Start();
                            sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(15));
                            _context.Log(LogLevel.Info, ModuleName, $"Service {svcName} restarted successfully");
                        }
                        catch (Exception ex)
                        {
                            _context.Log(LogLevel.Warning, ModuleName,
                                $"Could not restart {svcName}: {ex.Message}");
                        }

                        _context.RaiseAlert(new Alert
                        {
                            ModuleId = ModuleName,
                            Title = "Service Tamper Detected",
                            Message = $"Protected service {svcName} was stopped. Auto-restart attempted.",
                            Severity = AlertSeverity.Warning,
                            Timestamp = DateTime.UtcNow
                        });
                    }
                }
                catch (InvalidOperationException)
                {
                    // Service doesn't exist on this machine
                }
                catch { }
            }
        }

        private void StartProcessProtection()
        {
            try
            {
                var query = new WqlEventQuery(
                    "SELECT * FROM __InstanceDeletionEvent WITHIN 2 " +
                    "WHERE TargetInstance ISA 'Win32_Process'");

                _processWatcher = new ManagementEventWatcher(query);
                _processWatcher.EventArrived += OnProcessTerminated;
                _processWatcher.Start();
            }
            catch (Exception ex)
            {
                _context.Log(LogLevel.Warning, ModuleName,
                    $"Process protection WMI watcher failed: {ex.Message}");
            }
        }

        private void OnProcessTerminated(object sender, EventArrivedEventArgs e)
        {
            try
            {
                var target = (ManagementBaseObject)e.NewEvent["TargetInstance"];
                var name = target["Name"]?.ToString() ?? "";
                var processName = Path.GetFileNameWithoutExtension(name);

                if (!ProtectedProcesses.Contains(processName, StringComparer.OrdinalIgnoreCase))
                    return;

                if (processName.Equals("PCPlusTray", StringComparison.OrdinalIgnoreCase))
                {
                    _context.Log(LogLevel.Warning, ModuleName,
                        "PCPlusTray was terminated. TrayWatchdog will restart it.");
                    _context.RaiseAlert(new Alert
                    {
                        ModuleId = ModuleName,
                        Title = "Tray App Terminated",
                        Message = "PCPlusTray process was killed. Auto-restart in progress.",
                        Severity = AlertSeverity.Warning,
                        Timestamp = DateTime.UtcNow
                    });
                }
            }
            catch { }
        }

        private void ProtectInstallation()
        {
            try
            {
                // Protect uninstall registry key - make it harder to silently uninstall
                var uninstallKey = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\PC Plus Endpoint Protection_is1",
                    writable: true);
                if (uninstallKey != null)
                {
                    uninstallKey.SetValue("NoRemove", 1, RegistryValueKind.DWord);
                    uninstallKey.SetValue("NoModify", 1, RegistryValueKind.DWord);
                    uninstallKey.Close();
                    _context.Log(LogLevel.Info, ModuleName, "Uninstall protection applied");
                }
            }
            catch (Exception ex)
            {
                _context.Log(LogLevel.Warning, ModuleName,
                    $"Uninstall protection failed: {ex.Message}");
            }

            try
            {
                // Protect the data directory with restrictive ACLs
                var dataDir = new DirectoryInfo(DataDir);
                if (dataDir.Exists)
                {
                    var security = dataDir.GetAccessControl();
                    var everyoneSid = new System.Security.Principal.SecurityIdentifier(
                        System.Security.Principal.WellKnownSidType.WorldSid, null);
                    security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                        everyoneSid,
                        System.Security.AccessControl.FileSystemRights.Delete |
                        System.Security.AccessControl.FileSystemRights.DeleteSubdirectoriesAndFiles,
                        System.Security.AccessControl.InheritanceFlags.ContainerInherit |
                        System.Security.AccessControl.InheritanceFlags.ObjectInherit,
                        System.Security.AccessControl.PropagationFlags.None,
                        System.Security.AccessControl.AccessControlType.Deny));
                    dataDir.SetAccessControl(security);
                    _context.Log(LogLevel.Info, ModuleName, "Data directory deletion protection applied");
                }
            }
            catch (Exception ex)
            {
                _context.Log(LogLevel.Warning, ModuleName,
                    $"Data directory protection failed: {ex.Message}");
            }
        }
    }
}
