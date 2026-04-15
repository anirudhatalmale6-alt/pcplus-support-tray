using System.Diagnostics;
using System.Management;
using System.Text.Json;
using System.Text.RegularExpressions;
using PCPlus.Core.Interfaces;
using PCPlus.Core.Models;

namespace PCPlus.Service.Modules.Ransomware
{
    /// <summary>
    /// Ransomware detection and auto-response module.
    /// 5-layer defense: honeypot files, behavior detection, process monitoring,
    /// shadow copy protection, auto-containment + lockdown.
    /// Premium tier.
    /// </summary>
    public class RansomwareModule : IModule
    {
        public string Id => "ransomware";
        public string Name => "Ransomware Protection";
        public string Version => "4.0.0";
        public LicenseTier RequiredTier => LicenseTier.Premium;
        public bool IsRunning { get; private set; }

        private IModuleContext _context = null!;
        private readonly List<ThreatDetection> _detections = new();
        private readonly object _lock = new();
        private LockdownState _lockdownState = new();
        private FileSystemWatcher?[] _watchers = Array.Empty<FileSystemWatcher>();
        private Timer? _processMonitor;
        private readonly HashSet<string> _honeypotFiles = new();

        // Known ransomware file extensions
        private static readonly HashSet<string> RansomwareExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".encrypted", ".locked", ".crypto", ".crypt", ".enc", ".locky",
            ".cerber", ".zepto", ".thor", ".aesir", ".zzzzz", ".micro",
            ".vvv", ".ccc", ".abc", ".ecc", ".ezz", ".exx",
            ".wncry", ".wcry", ".wnry", ".wncrypt",
            ".WANNA_DECRYPT", ".REVENGE", ".GANDCRAB",
            ".CONTI", ".HIVE", ".LOCKBIT", ".BLACKCAT",
            ".revil", ".sodinokibi", ".ryuk", ".maze", ".clop",
            ".ransomware", ".pays", ".ransom"
        };

        // Known ransomware note filenames
        private static readonly HashSet<string> RansomNoteNames = new(StringComparer.OrdinalIgnoreCase)
        {
            "README_TO_DECRYPT.txt", "HOW_TO_DECRYPT.txt", "DECRYPT_INSTRUCTIONS.txt",
            "YOUR_FILES_ARE_ENCRYPTED.txt", "RECOVERY_INSTRUCTIONS.txt",
            "_readme.txt", "HELP_RECOVER.txt", "!!! READ ME !!!.txt",
            "RESTORE_FILES.txt", "ATTENTION!!!.txt", "warning.html",
            "HOW-TO-DECRYPT-FILES.txt", "HELP_DECRYPT.html",
            "ransom_note.txt", "!_HOW_RECOVERY.txt", "DECRYPT_YOUR_FILES.html"
        };

        // Suspicious PowerShell patterns
        private static readonly string[] SuspiciousPsPatterns = new[]
        {
            "-enc ", "-encodedcommand", "frombase64string", "downloadstring",
            "invoke-expression", "iex ", "bypass", "-nop ", "-w hidden",
            "invoke-webrequest", "net.webclient", "start-bitstransfer",
            "invoke-mimikatz", "invoke-shellcode"
        };

        public Task InitializeAsync(IModuleContext context)
        {
            _context = context;
            return Task.CompletedTask;
        }

        public Task StartAsync(CancellationToken cancellationToken)
        {
            if (!_context.Config.RansomwareProtectionEnabled)
            {
                _context.Log(LogLevel.Info, Id, "Ransomware protection disabled in config");
                return Task.CompletedTask;
            }

            IsRunning = true;
            _context.Log(LogLevel.Info, Id, "Starting ransomware protection...");

            // Deploy honeypot files
            DeployHoneypotFiles();

            // Set up file system watchers on user-accessible drives
            SetupFileWatchers();

            // Start process monitoring (every 3 seconds)
            _processMonitor = new Timer(MonitorProcesses, null, 0, 3000);

            _context.Log(LogLevel.Info, Id, $"Ransomware protection active. {_honeypotFiles.Count} honeypot files deployed.");
            return Task.CompletedTask;
        }

        public Task StopAsync()
        {
            foreach (var w in _watchers) w?.Dispose();
            _watchers = Array.Empty<FileSystemWatcher>();
            _processMonitor?.Dispose();
            IsRunning = false;
            return Task.CompletedTask;
        }

        public Task<ModuleResponse> HandleCommandAsync(ModuleCommand command)
        {
            switch (command.Action)
            {
                case "GetThreatStatus":
                    lock (_lock)
                    {
                        return Task.FromResult(ModuleResponse.Ok("", new Dictionary<string, object>
                        {
                            ["detections"] = new List<ThreatDetection>(_detections),
                            ["lockdown"] = _lockdownState,
                            ["honeypotCount"] = _honeypotFiles.Count
                        }));
                    }

                case "GetLockdownState":
                    return Task.FromResult(ModuleResponse.Ok("", new Dictionary<string, object>
                    {
                        ["lockdown"] = _lockdownState
                    }));

                case "ActivateLockdown":
                    ActivateLockdown("Manual activation from dashboard");
                    return Task.FromResult(ModuleResponse.Ok("Lockdown activated"));

                case "DeactivateLockdown":
                    DeactivateLockdown();
                    return Task.FromResult(ModuleResponse.Ok("Lockdown deactivated"));

                case "event":
                    // Handle inter-module events
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
            StatusText = _lockdownState.IsActive ? "LOCKDOWN ACTIVE" :
                         IsRunning ? $"Active ({_honeypotFiles.Count} honeypots)" : "Stopped",
            LastActivity = DateTime.UtcNow,
            Metrics = new()
            {
                ["detectionCount"] = _detections.Count,
                ["lockdownActive"] = _lockdownState.IsActive,
                ["honeypotCount"] = _honeypotFiles.Count
            }
        };

        // --- Honeypot System ---

        private void DeployHoneypotFiles()
        {
            var locations = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonDocuments),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                Environment.GetFolderPath(Environment.SpecialFolder.MyPictures)
            };

            // Decoy filenames that look like real files
            var decoyNames = new[]
            {
                "!Important_Report_2026.docx",  // ! prefix = sorts first, ransomware hits it first
                "~$Budget_Summary_Q1.xlsx",
                "!Company_Accounts.pdf",
                "~$Project_Timeline.docx",
                "!Invoice_Records.csv"
            };

            int count = Math.Min(_context.Config.HoneypotFileCount, decoyNames.Length);

            foreach (var dir in locations)
            {
                if (!Directory.Exists(dir)) continue;

                for (int i = 0; i < count; i++)
                {
                    try
                    {
                        var path = Path.Combine(dir, decoyNames[i]);
                        if (!File.Exists(path))
                        {
                            // Create a small file with convincing content
                            File.WriteAllText(path, GenerateDecoyContent(decoyNames[i]));
                            // Mark as hidden + system
                            File.SetAttributes(path, FileAttributes.Hidden | FileAttributes.System);
                        }
                        _honeypotFiles.Add(path.ToLower());
                    }
                    catch { }
                }
            }
        }

        private static string GenerateDecoyContent(string filename)
        {
            // Small realistic-looking content that won't confuse users if found
            return $"PC Plus Endpoint Protection - Decoy File\n" +
                   $"This file is monitored for ransomware detection.\n" +
                   $"Do not delete or modify.\n" +
                   $"File: {filename}\n" +
                   $"Created: {DateTime.UtcNow:yyyy-MM-dd}\n" +
                   new string('A', 512); // Padding to make it look like a real file
        }

        // --- File System Monitoring ---

        private void SetupFileWatchers()
        {
            var paths = new List<string>();
            foreach (var drive in DriveInfo.GetDrives())
            {
                if (drive.IsReady && drive.DriveType == DriveType.Fixed)
                {
                    // Watch user directories, not entire drive (performance)
                    var userDirs = new[]
                    {
                        Path.Combine(drive.RootDirectory.FullName, "Users"),
                        Environment.GetFolderPath(Environment.SpecialFolder.CommonDocuments)
                    };
                    foreach (var dir in userDirs)
                    {
                        if (Directory.Exists(dir)) paths.Add(dir);
                    }
                }
            }

            _watchers = paths.Select(path =>
            {
                try
                {
                    var w = new FileSystemWatcher(path)
                    {
                        IncludeSubdirectories = true,
                        EnableRaisingEvents = true,
                        NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite |
                                       NotifyFilters.CreationTime
                    };
                    w.Changed += OnFileChanged;
                    w.Created += OnFileCreated;
                    w.Renamed += OnFileRenamed;
                    return w;
                }
                catch
                {
                    return null;
                }
            }).Where(w => w != null).ToArray()!;
        }

        private void OnFileChanged(object sender, FileSystemEventArgs e)
        {
            // Check if a honeypot file was modified
            if (_honeypotFiles.Contains(e.FullPath.ToLower()))
            {
                OnHoneypotTriggered(e.FullPath, "modified");
                return;
            }
        }

        private void OnFileCreated(object sender, FileSystemEventArgs e)
        {
            var ext = Path.GetExtension(e.FullPath);
            var name = Path.GetFileName(e.FullPath);

            // Check for ransomware note creation
            if (RansomNoteNames.Contains(name))
            {
                RecordThreat(ThreatType.RansomNote, ThreatSeverity.Critical,
                    $"Ransomware note detected: {name}", new[] { e.FullPath });
            }

            // Check for known ransomware extensions
            if (RansomwareExtensions.Contains(ext))
            {
                RecordThreat(ThreatType.FileEncryption, ThreatSeverity.Critical,
                    $"File with ransomware extension created: {name}", new[] { e.FullPath });
            }
        }

        private void OnFileRenamed(object sender, RenamedEventArgs e)
        {
            // Check for honeypot rename
            if (_honeypotFiles.Contains(e.OldFullPath.ToLower()))
            {
                OnHoneypotTriggered(e.OldFullPath, $"renamed to {e.FullPath}");
                return;
            }

            // Check for mass extension changes (ransomware signature)
            var newExt = Path.GetExtension(e.FullPath);
            if (RansomwareExtensions.Contains(newExt))
            {
                RecordThreat(ThreatType.MassFileRename, ThreatSeverity.High,
                    $"File renamed with ransomware extension: {e.OldName} -> {e.Name}",
                    new[] { e.FullPath });
            }
        }

        private void OnHoneypotTriggered(string filePath, string action)
        {
            _context.Log(LogLevel.Critical, Id, $"HONEYPOT TRIGGERED: {filePath} was {action}");

            RecordThreat(ThreatType.HoneypotTriggered, ThreatSeverity.Critical,
                $"Decoy file {action}: {Path.GetFileName(filePath)}", new[] { filePath });

            // Immediate lockdown if enabled
            if (_context.Config.LockdownOnDetection)
            {
                ActivateLockdown($"Honeypot triggered: {filePath}");
            }
        }

        // --- Process Monitoring ---

        private void MonitorProcesses(object? state)
        {
            try
            {
                var processes = Process.GetProcesses();
                foreach (var proc in processes)
                {
                    try
                    {
                        CheckSuspiciousProcess(proc);
                    }
                    catch { }
                    finally { proc.Dispose(); }
                }
            }
            catch { }
        }

        private void CheckSuspiciousProcess(Process proc)
        {
            try
            {
                var name = proc.ProcessName.ToLower();
                var cmdLine = GetProcessCommandLine(proc.Id);

                // Check for vssadmin shadow copy deletion
                if (name == "vssadmin" && cmdLine.Contains("delete", StringComparison.OrdinalIgnoreCase) &&
                    cmdLine.Contains("shadows", StringComparison.OrdinalIgnoreCase))
                {
                    RecordThreat(ThreatType.ShadowCopyDeletion, ThreatSeverity.Critical,
                        $"Shadow copy deletion detected: {cmdLine}",
                        processName: proc.ProcessName, processId: proc.Id);

                    if (_context.Config.AutoContainmentEnabled)
                    {
                        KillProcess(proc.Id, "Shadow copy deletion");
                    }
                }

                // Check for suspicious PowerShell
                if ((name == "powershell" || name == "pwsh") &&
                    SuspiciousPsPatterns.Any(p => cmdLine.Contains(p, StringComparison.OrdinalIgnoreCase)))
                {
                    RecordThreat(ThreatType.PowerShellAbuse, ThreatSeverity.High,
                        $"Suspicious PowerShell: {TruncateString(cmdLine, 200)}",
                        processName: proc.ProcessName, processId: proc.Id);

                    // Use AI analysis if available
                    if (_context.AiAnalyzer?.IsAvailable == true)
                    {
                        _ = AnalyzeWithAiAsync(proc.ProcessName, cmdLine, proc.Id);
                    }
                }

                // Check for known ransomware process names
                if (IsKnownRansomwareProcess(name))
                {
                    RecordThreat(ThreatType.SuspiciousProcess, ThreatSeverity.Critical,
                        $"Known ransomware process: {proc.ProcessName}",
                        processName: proc.ProcessName, processId: proc.Id);

                    if (_context.Config.AutoContainmentEnabled)
                    {
                        KillProcess(proc.Id, "Known ransomware process");
                        if (_context.Config.LockdownOnDetection)
                            ActivateLockdown($"Ransomware process detected: {proc.ProcessName}");
                    }
                }
            }
            catch { }
        }

        private async Task AnalyzeWithAiAsync(string processName, string cmdLine, int pid)
        {
            try
            {
                var result = await _context.AiAnalyzer!.ClassifyProcessAsync(new ProcessAnalysisContext
                {
                    ProcessName = processName,
                    CommandLine = cmdLine
                });

                if (result.ShouldBlock)
                {
                    _context.Log(LogLevel.Warning, Id,
                        $"AI classified {processName} as {result.Classification} (confidence: {result.Confidence:P0})");
                    if (_context.Config.AutoContainmentEnabled)
                        KillProcess(pid, $"AI analysis: {result.Classification}");
                }
            }
            catch { }
        }

        // --- Containment and Lockdown ---

        private void RecordThreat(ThreatType type, ThreatSeverity severity, string description,
            string[]? affectedFiles = null, string processName = "", int processId = 0)
        {
            var threat = new ThreatDetection
            {
                Type = type,
                Severity = severity,
                Description = description,
                AffectedFiles = affectedFiles ?? Array.Empty<string>(),
                ProcessName = processName,
                ProcessId = processId,
                DetectedAt = DateTime.UtcNow
            };

            lock (_lock) { _detections.Add(threat); }

            _context.RaiseAlert(new Alert
            {
                ModuleId = Id,
                Title = $"Threat Detected: {type}",
                Message = description,
                Severity = severity >= ThreatSeverity.High ? AlertSeverity.Emergency : AlertSeverity.Critical,
                Category = "ransomware",
                Metadata = new()
                {
                    ["threatType"] = type.ToString(),
                    ["processName"] = processName,
                    ["processId"] = processId.ToString()
                }
            });

            _ = _context.BroadcastEventAsync(new ModuleEvent
            {
                SourceModule = Id,
                EventType = ModuleEvent.THREAT_DETECTED,
                Data = new() { ["threat"] = threat }
            });
        }

        private void ActivateLockdown(string reason)
        {
            if (_lockdownState.IsActive) return;

            _context.Log(LogLevel.Critical, Id, $"LOCKDOWN ACTIVATED: {reason}");

            _lockdownState = new LockdownState
            {
                IsActive = true,
                ActivatedAt = DateTime.UtcNow,
                Reason = reason,
                TriggeredBy = Id,
                ActiveActions = new LockdownActions()
            };

            // Kill suspicious processes
            lock (_lock)
            {
                foreach (var detection in _detections.Where(d => d.ProcessId > 0 && !d.Contained))
                {
                    KillProcess(detection.ProcessId, "Lockdown");
                    detection.Contained = true;
                    _lockdownState.ActiveActions.KilledProcessIds.Add(detection.ProcessId);
                    _lockdownState.ActiveActions.KilledProcessNames.Add(detection.ProcessName);
                }
            }

            // Disable network (if configured)
            if (_context.Config.AutoContainmentEnabled)
            {
                DisableNetwork();
                _lockdownState.ActiveActions.NetworkDisabled = true;
            }

            // Block RDP
            DisableRDP();
            _lockdownState.ActiveActions.RdpDisabled = true;

            _ = _context.BroadcastEventAsync(new ModuleEvent
            {
                SourceModule = Id,
                EventType = ModuleEvent.LOCKDOWN_ACTIVATED,
                Data = new() { ["reason"] = reason }
            });
        }

        private void DeactivateLockdown()
        {
            if (!_lockdownState.IsActive) return;

            _context.Log(LogLevel.Info, Id, "Lockdown deactivated");

            // Re-enable network
            if (_lockdownState.ActiveActions.NetworkDisabled)
                EnableNetwork();

            // Re-enable RDP
            if (_lockdownState.ActiveActions.RdpDisabled)
                EnableRDP();

            _lockdownState = new LockdownState();

            _ = _context.BroadcastEventAsync(new ModuleEvent
            {
                SourceModule = Id,
                EventType = ModuleEvent.LOCKDOWN_DEACTIVATED
            });
        }

        // --- System Actions ---

        private void KillProcess(int pid, string reason)
        {
            try
            {
                var proc = Process.GetProcessById(pid);
                _context.Log(LogLevel.Warning, Id, $"Killing process {proc.ProcessName} (PID {pid}): {reason}");
                proc.Kill(true);
            }
            catch { }
        }

        private void DisableNetwork()
        {
            try
            {
                // Disable all network adapters via netsh
                RunCommand("netsh", "interface set interface name=\"*\" admin=disable");
                _context.Log(LogLevel.Warning, Id, "Network adapters disabled (lockdown)");
            }
            catch { }
        }

        private void EnableNetwork()
        {
            try
            {
                RunCommand("netsh", "interface set interface name=\"*\" admin=enable");
                _context.Log(LogLevel.Info, Id, "Network adapters re-enabled");
            }
            catch { }
        }

        private void DisableRDP()
        {
            try
            {
                RunCommand("reg", "add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\" /v fDenyTSConnections /t REG_DWORD /d 1 /f");
                _context.Log(LogLevel.Warning, Id, "RDP disabled (lockdown)");
            }
            catch { }
        }

        private void EnableRDP()
        {
            try
            {
                RunCommand("reg", "add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\" /v fDenyTSConnections /t REG_DWORD /d 0 /f");
                _context.Log(LogLevel.Info, Id, "RDP re-enabled");
            }
            catch { }
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

        private static string GetProcessCommandLine(int pid)
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    $"SELECT CommandLine FROM Win32_Process WHERE ProcessId={pid}");
                foreach (ManagementObject obj in searcher.Get())
                    return obj["CommandLine"]?.ToString() ?? "";
            }
            catch { }
            return "";
        }

        private static bool IsKnownRansomwareProcess(string name)
        {
            // Known ransomware executable names (partial list)
            var known = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "wannacry", "wcry", "wncrypt", "tasksche",
                "cerber", "locky", "cryptolocker", "teslacrypt",
                "gandcrab", "sodinokibi", "ryuk", "conti",
                "lockbit", "blackcat", "alphv", "hive",
                "maze", "clop", "revil", "darkside",
                "babuk", "avaddon", "ragnar_locker"
            };
            return known.Contains(name);
        }

        private static string TruncateString(string s, int maxLen) =>
            s.Length <= maxLen ? s : s[..maxLen] + "...";
    }
}
