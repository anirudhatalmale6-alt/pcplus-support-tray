using System.Diagnostics;
using System.Management;
using System.Text.Json;
using Microsoft.Win32;
using PCPlus.Core.Interfaces;

namespace PCPlus.Service.Modules.Ransomware
{
    /// <summary>
    /// Advanced ransomware detection layer that goes beyond file-level monitoring:
    ///
    /// 1. Registry Sentinel: Watches autorun keys, services, scheduled tasks for
    ///    persistence mechanisms used by ransomware (Run, RunOnce, Services, etc.)
    /// 2. Boot Config Guard: Monitors bcdedit changes - ransomware disables recovery,
    ///    safe mode, and boot policies to prevent restoration.
    /// 3. Network Lateral Movement: Detects SMB brute force patterns, unusual share
    ///    access from the machine that could indicate ransomware spreading.
    /// 4. File Rollback Engine: Maintains shadow copies of recently modified files
    ///    in user directories. If ransomware encrypts files, we can restore from
    ///    our own backup (independent of VSS).
    /// 5. Safe Mode Boot Detection: Detects if the system was booted in safe mode
    ///    (some ransomware forces safe mode reboot to bypass security).
    /// 6. WMI Persistence Detection: Detects WMI event subscriptions used for persistence.
    /// </summary>
    public class AdvancedDetection : IDisposable
    {
        private IModuleContext _context = null!;
        private readonly BehaviorScoringEngine _scoring;
        private Timer? _registryMonitor;
        private Timer? _bootConfigCheck;
        private Timer? _networkMonitor;
        private Timer? _wmiPersistenceCheck;
        private Timer? _rollbackCleanup;
        private FileRollbackEngine? _rollback;
        private bool _isActive;

        private readonly Dictionary<string, string> _registryBaseline = new();
        private readonly List<AdvancedEvent> _events = new();
        private readonly object _lock = new();
        private string _bootConfigBaseline = "";
        private int _detectionCount;

        // Registry keys ransomware uses for persistence
        private static readonly (string hive, string path, string description)[] WatchedRegistryKeys = new[]
        {
            ("HKLM", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "Machine autorun"),
            ("HKLM", @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "Machine run-once"),
            ("HKCU", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "User autorun"),
            ("HKCU", @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "User run-once"),
            ("HKLM", @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices", "Service autorun"),
            ("HKLM", @"SYSTEM\CurrentControlSet\Services", "Windows services"),
            ("HKLM", @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "Winlogon hooks"),
            ("HKLM", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders", "Shell folders"),
            ("HKLM", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "System policies"),
        };

        // Network indicators of lateral movement
        private static readonly int[] SmbPorts = { 445, 139, 135, 3389 };

        public AdvancedDetection(BehaviorScoringEngine scoring)
        {
            _scoring = scoring;
        }

        public void Start(IModuleContext context, string rollbackDir)
        {
            _context = context;
            _isActive = true;

            CaptureRegistryBaseline();
            CaptureBootConfigBaseline();
            CheckSafeModeBoot();

            _rollback = new FileRollbackEngine(context, rollbackDir);
            _rollback.Start();

            // Registry monitoring - configurable (default 10s, critical for detecting persistence)
            var regMs = context.Config.GetValue("advancedDetectionRegistryMs") is string rv && int.TryParse(rv, out var rm) ? rm : 10000;
            _registryMonitor = new Timer(ScanRegistry, null, TimeSpan.FromMilliseconds(regMs), TimeSpan.FromMilliseconds(regMs));

            // Boot config check every 5 minutes (non-critical, rarely changes)
            _bootConfigCheck = new Timer(CheckBootConfig, null, TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(5));

            // Network lateral movement detection - configurable (default 30s, runs netstat -ano)
            var netMs = context.Config.GetValue("advancedDetectionNetworkMs") is string nv && int.TryParse(nv, out var nm) ? nm : 30000;
            _networkMonitor = new Timer(MonitorNetwork, null, TimeSpan.FromMilliseconds(netMs), TimeSpan.FromMilliseconds(netMs));

            // WMI persistence check every 2 minutes
            _wmiPersistenceCheck = new Timer(CheckWmiPersistence, null, TimeSpan.FromMinutes(2), TimeSpan.FromMinutes(2));

            // Rollback cleanup (prune old snapshots) every hour
            _rollbackCleanup = new Timer(_ => _rollback?.Cleanup(), null, TimeSpan.FromHours(1), TimeSpan.FromHours(1));

            _context.Log(LogLevel.Info, "ransomware",
                "Advanced Detection active: registry sentinel, boot guard, network monitor, file rollback, WMI persistence check");
        }

        public void Stop()
        {
            _isActive = false;
            _registryMonitor?.Dispose();
            _bootConfigCheck?.Dispose();
            _networkMonitor?.Dispose();
            _wmiPersistenceCheck?.Dispose();
            _rollbackCleanup?.Dispose();
            _rollback?.Stop();
        }

        public AdvancedDetectionStatus GetStatus()
        {
            return new AdvancedDetectionStatus
            {
                IsActive = _isActive,
                DetectionCount = _detectionCount,
                RollbackFilesCount = _rollback?.FileCount ?? 0,
                RollbackSizeMb = _rollback?.TotalSizeMb ?? 0,
                RecentEvents = _events.TakeLast(20).Reverse().ToList()
            };
        }

        public FileRollbackEngine? Rollback => _rollback;

        #region Registry Sentinel

        private void CaptureRegistryBaseline()
        {
            try
            {
                foreach (var (hive, path, _) in WatchedRegistryKeys)
                {
                    var root = hive == "HKLM" ? Registry.LocalMachine : Registry.CurrentUser;
                    using var key = root.OpenSubKey(path);
                    if (key == null) continue;

                    foreach (var valueName in key.GetValueNames())
                    {
                        var fullKey = $"{hive}\\{path}\\{valueName}";
                        var value = key.GetValue(valueName)?.ToString() ?? "";
                        _registryBaseline[fullKey] = value;
                    }
                }
                _context.Log(LogLevel.Info, "ransomware", $"Registry baseline captured: {_registryBaseline.Count} values");
            }
            catch (Exception ex)
            {
                _context.Log(LogLevel.Warning, "ransomware", $"Registry baseline capture failed: {ex.Message}");
            }
        }

        private void ScanRegistry(object? state)
        {
            try
            {
                foreach (var (hive, path, description) in WatchedRegistryKeys)
                {
                    var root = hive == "HKLM" ? Registry.LocalMachine : Registry.CurrentUser;
                    using var key = root.OpenSubKey(path);
                    if (key == null) continue;

                    foreach (var valueName in key.GetValueNames())
                    {
                        var fullKey = $"{hive}\\{path}\\{valueName}";
                        var currentValue = key.GetValue(valueName)?.ToString() ?? "";

                        if (!_registryBaseline.TryGetValue(fullKey, out var baselineValue))
                        {
                            // New entry added
                            _registryBaseline[fullKey] = currentValue;

                            if (IsSuspiciousRegistryValue(currentValue))
                            {
                                _detectionCount++;
                                var detail = $"Suspicious registry addition in {description}: {valueName} = {Truncate(currentValue, 200)}";
                                _context.Log(LogLevel.Warning, "ransomware", $"Advanced Detection: {detail}");

                                RecordEvent("registry_add", fullKey, detail);

                                _context.RaiseAlert(new PCPlus.Core.Models.Alert
                                {
                                    ModuleId = "ransomware",
                                    Title = "Suspicious Registry Modification",
                                    Message = detail,
                                    Severity = PCPlus.Core.Models.AlertSeverity.Critical,
                                    Category = "ransomware"
                                });
                            }
                        }
                        else if (currentValue != baselineValue)
                        {
                            // Value changed
                            _registryBaseline[fullKey] = currentValue;

                            if (IsSuspiciousRegistryValue(currentValue))
                            {
                                _detectionCount++;
                                var detail = $"Registry value changed in {description}: {valueName}\n" +
                                             $"Old: {Truncate(baselineValue, 100)}\nNew: {Truncate(currentValue, 100)}";
                                _context.Log(LogLevel.Warning, "ransomware", $"Advanced Detection: {detail}");
                                RecordEvent("registry_change", fullKey, detail);
                            }
                        }
                    }
                }
            }
            catch { }
        }

        private static bool IsSuspiciousRegistryValue(string value)
        {
            var lower = value.ToLower();
            return lower.Contains(@"\temp\") ||
                   lower.Contains(@"\appdata\") && lower.EndsWith(".exe") ||
                   lower.Contains("powershell") && lower.Contains("-enc") ||
                   lower.Contains("cmd.exe /c") ||
                   lower.Contains("mshta") ||
                   lower.Contains("wscript") && lower.Contains(@"\temp") ||
                   lower.Contains("regsvr32") && lower.Contains("/s") ||
                   lower.Contains("rundll32") && lower.Contains(",") && lower.Contains(@"\temp");
        }

        #endregion

        #region Boot Config Guard

        private void CaptureBootConfigBaseline()
        {
            try
            {
                _bootConfigBaseline = RunCommandOutput("bcdedit", "/enum");
                _context.Log(LogLevel.Info, "ransomware", "Boot configuration baseline captured");
            }
            catch (Exception ex)
            {
                _context.Log(LogLevel.Warning, "ransomware", $"Boot config baseline failed: {ex.Message}");
            }
        }

        private void CheckBootConfig(object? state)
        {
            try
            {
                var current = RunCommandOutput("bcdedit", "/enum");
                if (string.IsNullOrEmpty(current) || string.IsNullOrEmpty(_bootConfigBaseline))
                    return;

                // Check for dangerous changes
                bool recoveryDisabled = current.Contains("recoveryenabled            No", StringComparison.OrdinalIgnoreCase)
                    && !_bootConfigBaseline.Contains("recoveryenabled            No", StringComparison.OrdinalIgnoreCase);

                bool bootPolicyChanged = current.Contains("bootstatuspolicy", StringComparison.OrdinalIgnoreCase)
                    && !_bootConfigBaseline.Contains("bootstatuspolicy", StringComparison.OrdinalIgnoreCase);

                bool safeModeAdded = current.Contains("safeboot", StringComparison.OrdinalIgnoreCase)
                    && !_bootConfigBaseline.Contains("safeboot", StringComparison.OrdinalIgnoreCase);

                if (recoveryDisabled || bootPolicyChanged || safeModeAdded)
                {
                    _detectionCount++;
                    var changes = new List<string>();
                    if (recoveryDisabled) changes.Add("Recovery disabled");
                    if (bootPolicyChanged) changes.Add("Boot policy changed");
                    if (safeModeAdded) changes.Add("Safe mode boot configured");

                    var detail = $"Boot configuration tampered: {string.Join(", ", changes)}";
                    _context.Log(LogLevel.Critical, "ransomware", $"Advanced Detection: {detail}");

                    RecordEvent("boot_config_tampered", "bcdedit", detail);

                    _context.RaiseAlert(new PCPlus.Core.Models.Alert
                    {
                        ModuleId = "ransomware",
                        Title = "Boot Configuration Tampered",
                        Message = $"{detail}\n\nThis is a common ransomware technique to prevent system recovery. " +
                                  "Attempting to restore boot configuration.",
                        Severity = PCPlus.Core.Models.AlertSeverity.Emergency,
                        Category = "ransomware"
                    });

                    // Auto-restore boot config
                    RestoreBootConfig(recoveryDisabled, safeModeAdded);
                }

                _bootConfigBaseline = current;
            }
            catch { }
        }

        private void RestoreBootConfig(bool restoreRecovery, bool removeSafeMode)
        {
            try
            {
                if (restoreRecovery)
                {
                    RunCommand("bcdedit", "/set {default} recoveryenabled Yes");
                    _context.Log(LogLevel.Warning, "ransomware", "Boot config restored: recovery re-enabled");
                }
                if (removeSafeMode)
                {
                    RunCommand("bcdedit", "/deletevalue {default} safeboot");
                    _context.Log(LogLevel.Warning, "ransomware", "Boot config restored: safe mode boot removed");
                }
                RecordEvent("boot_config_restored", "bcdedit", "Boot configuration auto-restored after tampering");
            }
            catch (Exception ex)
            {
                _context.Log(LogLevel.Error, "ransomware", $"Failed to restore boot config: {ex.Message}");
            }
        }

        private void CheckSafeModeBoot()
        {
            try
            {
                // Check if we're currently in safe mode (ransomware sometimes forces reboot to safe mode)
                var bootMode = Environment.GetEnvironmentVariable("SAFEBOOT_OPTION");
                if (!string.IsNullOrEmpty(bootMode))
                {
                    _context.Log(LogLevel.Critical, "ransomware",
                        $"SAFE MODE BOOT DETECTED: {bootMode}. This may indicate ransomware forced a safe mode reboot.");

                    _context.RaiseAlert(new PCPlus.Core.Models.Alert
                    {
                        ModuleId = "ransomware",
                        Title = "Safe Mode Boot Detected",
                        Message = $"System booted in safe mode ({bootMode}). Some ransomware forces safe mode reboot to bypass security. Investigate immediately.",
                        Severity = PCPlus.Core.Models.AlertSeverity.Emergency,
                        Category = "ransomware"
                    });

                    RecordEvent("safe_mode_boot", "system", $"System in safe mode: {bootMode}");
                }
            }
            catch { }
        }

        #endregion

        #region Network Lateral Movement Detection

        private void MonitorNetwork(object? state)
        {
            try
            {
                // Check for unusual outbound SMB connections (ransomware spreading)
                var connections = GetActiveConnections();
                var smbOutbound = connections.Where(c =>
                    SmbPorts.Contains(c.RemotePort) &&
                    c.State == "ESTABLISHED" &&
                    !c.RemoteAddress.StartsWith("127.") &&
                    c.RemoteAddress != "0.0.0.0")
                    .ToList();

                // More than 10 simultaneous SMB connections is suspicious
                if (smbOutbound.Count > 10)
                {
                    _detectionCount++;
                    var targets = smbOutbound.Select(c => c.RemoteAddress).Distinct().Take(5);
                    var detail = $"Unusual SMB activity: {smbOutbound.Count} connections to {string.Join(", ", targets)}";

                    _context.Log(LogLevel.Warning, "ransomware", $"Advanced Detection: {detail}");
                    RecordEvent("lateral_movement", "network", detail);

                    // Find the process making these connections
                    foreach (var conn in smbOutbound.Take(5))
                    {
                        if (conn.ProcessId > 0)
                        {
                            var procName = GetProcessName(conn.ProcessId);
                            _scoring.AddSignal(conn.ProcessId, procName, BehaviorSignal.SuspiciousParentChild,
                                $"Mass SMB connections: {smbOutbound.Count} active");
                        }
                    }
                }

                // Check for rapid connection attempts to many hosts on RDP/SMB (brute force scanning)
                var uniqueTargets = smbOutbound.Select(c => c.RemoteAddress).Distinct().Count();
                if (uniqueTargets > 5)
                {
                    _detectionCount++;
                    _context.Log(LogLevel.Warning, "ransomware",
                        $"Advanced Detection: SMB connections to {uniqueTargets} unique hosts - possible lateral movement");

                    _context.RaiseAlert(new PCPlus.Core.Models.Alert
                    {
                        ModuleId = "ransomware",
                        Title = "Possible Lateral Movement Detected",
                        Message = $"Detected SMB/RDP connections to {uniqueTargets} unique hosts. Ransomware often spreads laterally via SMB shares.",
                        Severity = PCPlus.Core.Models.AlertSeverity.Critical,
                        Category = "ransomware"
                    });
                }
            }
            catch { }
        }

        private static List<NetworkConnection> GetActiveConnections()
        {
            var connections = new List<NetworkConnection>();
            try
            {
                var output = RunCommandOutput("netstat", "-ano");
                foreach (var line in output.Split('\n'))
                {
                    var parts = line.Trim().Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length < 5 || parts[0] != "TCP") continue;

                    var local = parts[1];
                    var remote = parts[2];
                    var state = parts[3];
                    int.TryParse(parts[4], out var pid);

                    var remotePort = 0;
                    var remoteAddr = remote;
                    var colonIdx = remote.LastIndexOf(':');
                    if (colonIdx > 0)
                    {
                        remoteAddr = remote[..colonIdx];
                        int.TryParse(remote[(colonIdx + 1)..], out remotePort);
                    }

                    connections.Add(new NetworkConnection
                    {
                        RemoteAddress = remoteAddr,
                        RemotePort = remotePort,
                        State = state,
                        ProcessId = pid
                    });
                }
            }
            catch { }
            return connections;
        }

        #endregion

        #region WMI Persistence Detection

        private void CheckWmiPersistence(object? state)
        {
            try
            {
                // Check for WMI event subscriptions (common ransomware persistence mechanism)
                using var filterSearcher = new ManagementObjectSearcher(
                    new ManagementScope(@"\\.\root\subscription"),
                    new ObjectQuery("SELECT * FROM __EventFilter"));

                var suspiciousFilters = new List<string>();
                foreach (ManagementObject obj in filterSearcher.Get())
                {
                    var name = obj["Name"]?.ToString() ?? "";
                    var query = obj["Query"]?.ToString() ?? "";

                    // Skip known-good system filters
                    if (name.StartsWith("SCM Event") || name.StartsWith("BVT") ||
                        name.Contains("Microsoft") || name.Contains("Windows"))
                        continue;

                    // Suspicious if it watches for startup events or runs commands
                    if (query.Contains("Win32_ProcessStartTrace") ||
                        query.Contains("__InstanceCreationEvent") && !name.Contains("PCPlus"))
                    {
                        suspiciousFilters.Add($"{name}: {Truncate(query, 100)}");
                    }

                    obj.Dispose();
                }

                if (suspiciousFilters.Count > 0)
                {
                    _detectionCount++;
                    var detail = $"Suspicious WMI persistence: {string.Join("; ", suspiciousFilters)}";
                    _context.Log(LogLevel.Warning, "ransomware", $"Advanced Detection: {detail}");
                    RecordEvent("wmi_persistence", "wmi", detail);
                }
            }
            catch { }
        }

        #endregion

        #region Utilities

        private void RecordEvent(string type, string source, string detail)
        {
            lock (_lock)
            {
                _events.Add(new AdvancedEvent
                {
                    Type = type,
                    Source = source,
                    Detail = detail,
                    Timestamp = DateTime.UtcNow
                });
                if (_events.Count > 1000)
                    _events.RemoveRange(0, _events.Count - 500);
            }
        }

        private static string RunCommandOutput(string fileName, string arguments)
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
                proc?.WaitForExit(10000);
                return output;
            }
            catch { return ""; }
        }

        private static void RunCommand(string fileName, string arguments)
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
            proc?.WaitForExit(10000);
        }

        private static string GetProcessName(int pid)
        {
            try { return Process.GetProcessById(pid).ProcessName; }
            catch { return "unknown"; }
        }

        private static string Truncate(string s, int max) =>
            s.Length <= max ? s : s[..max] + "...";

        #endregion

        public void Dispose()
        {
            Stop();
        }
    }

    /// <summary>
    /// Independent file rollback engine - keeps our own shadow copies
    /// of recently modified files, independent of Windows VSS.
    /// If ransomware encrypts files, we can restore from our cache.
    /// </summary>
    public class FileRollbackEngine
    {
        private readonly IModuleContext _context;
        private readonly string _rollbackDir;
        private FileSystemWatcher?[] _watchers = Array.Empty<FileSystemWatcher>();
        private readonly Dictionary<string, RollbackEntry> _entries = new();
        private readonly object _lock = new();
        private long _totalSize;

        private const long MaxCacheSizeBytes = 500L * 1024 * 1024; // 500MB cap
        private const int MaxFileSize = 10 * 1024 * 1024; // Only cache files under 10MB

        // File types worth protecting (documents, images, code)
        private static readonly HashSet<string> ProtectedExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf",
            ".txt", ".csv", ".rtf", ".odt", ".ods",
            ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".psd",
            ".mp3", ".mp4", ".avi", ".mov", ".mkv",
            ".zip", ".7z", ".rar", ".tar", ".gz",
            ".sql", ".mdb", ".accdb", ".sqlite",
            ".dwg", ".dxf", ".ai", ".eps", ".svg",
            ".py", ".cs", ".java", ".cpp", ".h", ".js", ".ts", ".html",
            ".pst", ".ost", ".eml", ".msg",
            ".qbw", ".qbb", ".tax", ".sage"
        };

        public int FileCount { get { lock (_lock) return _entries.Count; } }
        public double TotalSizeMb { get { lock (_lock) return _totalSize / (1024.0 * 1024.0); } }

        public FileRollbackEngine(IModuleContext context, string rollbackDir)
        {
            _context = context;
            _rollbackDir = rollbackDir;
            Directory.CreateDirectory(rollbackDir);
            ProtectRollbackCache();
        }

        private void ProtectRollbackCache()
        {
            try
            {
                var dirInfo = new DirectoryInfo(_rollbackDir);
                dirInfo.Attributes |= FileAttributes.Hidden | FileAttributes.System;

                var security = dirInfo.GetAccessControl();
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
                dirInfo.SetAccessControl(security);
                _context.Log(LogLevel.Info, "rollback", "Rollback cache protected with ACL deny-delete");
            }
            catch (Exception ex)
            {
                _context.Log(LogLevel.Warning, "rollback", $"Could not protect rollback cache: {ex.Message}");
            }
        }

        public void Start()
        {
            var userDirs = new List<string>();
            foreach (var drive in DriveInfo.GetDrives())
            {
                if (drive.IsReady && drive.DriveType == DriveType.Fixed)
                {
                    var usersDir = Path.Combine(drive.RootDirectory.FullName, "Users");
                    if (Directory.Exists(usersDir)) userDirs.Add(usersDir);
                }
            }

            _watchers = userDirs.Select(dir =>
            {
                try
                {
                    var w = new FileSystemWatcher(dir)
                    {
                        IncludeSubdirectories = true,
                        EnableRaisingEvents = true,
                        NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName
                    };
                    w.Changed += OnFileModified;
                    return w;
                }
                catch { return null; }
            }).Where(w => w != null).ToArray()!;

            _context.Log(LogLevel.Info, "ransomware", $"File rollback engine active: watching {userDirs.Count} user directories");
        }

        public void Stop()
        {
            foreach (var w in _watchers) w?.Dispose();
            _watchers = Array.Empty<FileSystemWatcher>();
        }

        private void OnFileModified(object sender, FileSystemEventArgs e)
        {
            try
            {
                var ext = Path.GetExtension(e.FullPath);
                if (!ProtectedExtensions.Contains(ext)) return;

                var info = new FileInfo(e.FullPath);
                if (!info.Exists || info.Length > MaxFileSize || info.Length == 0) return;

                // Don't cache our own rollback files
                if (e.FullPath.Contains("PCPlusEndpoint")) return;

                CacheFile(e.FullPath, info.Length);
            }
            catch { }
        }

        private void CacheFile(string originalPath, long fileSize)
        {
            lock (_lock)
            {
                // Check if we already have a recent cache of this file (within 5 min)
                if (_entries.TryGetValue(originalPath.ToLower(), out var existing) &&
                    (DateTime.UtcNow - existing.CachedAt).TotalMinutes < 5)
                    return;

                // Enforce size cap
                while (_totalSize + fileSize > MaxCacheSizeBytes && _entries.Count > 0)
                {
                    var oldest = _entries.OrderBy(e => e.Value.CachedAt).First();
                    RemoveEntry(oldest.Key);
                }
            }

            try
            {
                var hash = originalPath.ToLower().GetHashCode().ToString("x8");
                var cachePath = Path.Combine(_rollbackDir, $"{hash}_{Path.GetFileName(originalPath)}");

                File.Copy(originalPath, cachePath, overwrite: true);

                lock (_lock)
                {
                    var key = originalPath.ToLower();
                    if (_entries.TryGetValue(key, out var old))
                    {
                        _totalSize -= old.FileSize;
                        try { File.Delete(old.CachePath); } catch { }
                    }

                    _entries[key] = new RollbackEntry
                    {
                        OriginalPath = originalPath,
                        CachePath = cachePath,
                        FileSize = fileSize,
                        CachedAt = DateTime.UtcNow
                    };
                    _totalSize += fileSize;
                }
            }
            catch { }
        }

        /// <summary>Restore all cached files to their original locations.</summary>
        public int RestoreAll()
        {
            int restored = 0;
            List<RollbackEntry> entries;
            lock (_lock) { entries = _entries.Values.ToList(); }

            foreach (var entry in entries)
            {
                try
                {
                    if (File.Exists(entry.CachePath))
                    {
                        var dir = Path.GetDirectoryName(entry.OriginalPath);
                        if (dir != null) Directory.CreateDirectory(dir);
                        File.Copy(entry.CachePath, entry.OriginalPath, overwrite: true);
                        restored++;
                    }
                }
                catch { }
            }

            _context.Log(LogLevel.Info, "ransomware", $"File rollback: restored {restored} files");
            return restored;
        }

        /// <summary>Restore a specific file.</summary>
        public bool RestoreFile(string originalPath)
        {
            lock (_lock)
            {
                if (!_entries.TryGetValue(originalPath.ToLower(), out var entry))
                    return false;

                try
                {
                    File.Copy(entry.CachePath, originalPath, overwrite: true);
                    return true;
                }
                catch { return false; }
            }
        }

        public void Cleanup()
        {
            lock (_lock)
            {
                var cutoff = DateTime.UtcNow.AddHours(-24);
                var expired = _entries.Where(e => e.Value.CachedAt < cutoff).Select(e => e.Key).ToList();
                foreach (var key in expired)
                    RemoveEntry(key);
            }
        }

        private void RemoveEntry(string key)
        {
            if (_entries.TryGetValue(key, out var entry))
            {
                _totalSize -= entry.FileSize;
                try { File.Delete(entry.CachePath); } catch { }
                _entries.Remove(key);
            }
        }
    }

    public class RollbackEntry
    {
        public string OriginalPath { get; set; } = "";
        public string CachePath { get; set; } = "";
        public long FileSize { get; set; }
        public DateTime CachedAt { get; set; }
    }

    public class AdvancedDetectionStatus
    {
        public bool IsActive { get; set; }
        public int DetectionCount { get; set; }
        public int RollbackFilesCount { get; set; }
        public double RollbackSizeMb { get; set; }
        public List<AdvancedEvent> RecentEvents { get; set; } = new();
    }

    public class AdvancedEvent
    {
        public string Type { get; set; } = "";
        public string Source { get; set; } = "";
        public string Detail { get; set; } = "";
        public DateTime Timestamp { get; set; }
    }

    public class NetworkConnection
    {
        public string RemoteAddress { get; set; } = "";
        public int RemotePort { get; set; }
        public string State { get; set; } = "";
        public int ProcessId { get; set; }
    }
}
