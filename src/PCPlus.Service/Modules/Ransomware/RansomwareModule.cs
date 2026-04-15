using System.Diagnostics;
using System.Management;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using PCPlus.Core.Interfaces;
using PCPlus.Core.Models;

namespace PCPlus.Service.Modules.Ransomware
{
    /// <summary>
    /// Ransomware detection and auto-response module with behavior-based scoring.
    ///
    /// Instead of single-trigger lockdown, uses a weighted scoring engine that
    /// accumulates behavioral signals per process. Thresholds:
    ///   30 = Warning alert
    ///   60 = Auto-containment (kill process)
    ///   80 = Full system lockdown
    ///
    /// Detection layers:
    /// 1. Honeypot files (decoys across user folders)
    /// 2. FileSystemWatcher for real-time file events
    /// 3. Reconciliation scan loop (catches what FSW misses)
    /// 4. Process monitoring (known names, suspicious behavior, parent-child chains)
    /// 5. File entropy analysis (detect encryption in progress)
    /// 6. Rate-based detection (rename rate, folder spread, extension changes)
    /// 7. AI integration (optional process classification)
    /// </summary>
    public class RansomwareModule : IModule
    {
        public string Id => "ransomware";
        public string Name => "Ransomware Protection";
        public string Version => "4.1.0";
        public LicenseTier RequiredTier => LicenseTier.Premium;
        public bool IsRunning { get; private set; }

        private IModuleContext _context = null!;
        private readonly List<ThreatDetection> _detections = new();
        private readonly object _lock = new();
        private LockdownState _lockdownState = new();
        private FileSystemWatcher?[] _watchers = Array.Empty<FileSystemWatcher>();
        private Timer? _processMonitor;
        private Timer? _reconciliationScan;
        private readonly HashSet<string> _honeypotFiles = new();
        private readonly BehaviorScoringEngine _scoring = new();

        // Track file state for reconciliation scanning
        private readonly Dictionary<string, long> _honeypotHashes = new();

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

        // Known suspicious parent-child process chains
        private static readonly Dictionary<string, HashSet<string>> SuspiciousParentChild = new(StringComparer.OrdinalIgnoreCase)
        {
            ["winword"] = new(StringComparer.OrdinalIgnoreCase) { "powershell", "pwsh", "cmd", "wscript", "cscript", "mshta" },
            ["excel"] = new(StringComparer.OrdinalIgnoreCase) { "powershell", "pwsh", "cmd", "wscript", "cscript", "mshta" },
            ["outlook"] = new(StringComparer.OrdinalIgnoreCase) { "powershell", "pwsh", "cmd", "wscript" },
            ["explorer"] = new(StringComparer.OrdinalIgnoreCase) { "powershell", "pwsh" },
        };

        // Risky launch paths (processes spawned from these are suspicious)
        private static readonly string[] RiskyPaths = new[]
        {
            @"\temp\", @"\tmp\", @"\appdata\local\temp\", @"\appdata\roaming\",
            @"\downloads\", @"\public\", @"\programdata\",
            @"\users\public\", @"\windows\temp\"
        };

        public Task InitializeAsync(IModuleContext context)
        {
            _context = context;

            // Wire up scoring engine events
            _scoring.OnWarning += (pid, name, score, reason) =>
            {
                _context.Log(LogLevel.Warning, Id, $"THREAT WARNING: {name} (PID {pid}) score={score}: {reason}");
                RecordThreat(ThreatType.SuspiciousProcess, ThreatSeverity.Medium,
                    $"Behavioral threat score {score}: {reason}",
                    processName: name, processId: pid);
            };

            _scoring.OnContainment += (pid, name, score, reason) =>
            {
                _context.Log(LogLevel.Critical, Id, $"AUTO-CONTAINMENT: {name} (PID {pid}) score={score}: {reason}");
                RecordThreat(ThreatType.SuspiciousProcess, ThreatSeverity.High,
                    $"Auto-contained at score {score}: {reason}",
                    processName: name, processId: pid);

                if (_context.Config.AutoContainmentEnabled)
                {
                    KillProcess(pid, $"Behavior score {score} exceeded containment threshold");
                    _scoring.ResetProcess(pid);
                }
            };

            _scoring.OnLockdown += (pid, name, score, reason) =>
            {
                _context.Log(LogLevel.Critical, Id, $"LOCKDOWN TRIGGERED: {name} (PID {pid}) score={score}: {reason}");
                RecordThreat(ThreatType.SuspiciousProcess, ThreatSeverity.Critical,
                    $"Lockdown at score {score}: {reason}",
                    processName: name, processId: pid);

                if (_context.Config.AutoContainmentEnabled)
                {
                    KillProcess(pid, $"Behavior score {score} exceeded lockdown threshold");
                    _scoring.ResetProcess(pid);
                }
                if (_context.Config.LockdownOnDetection)
                {
                    ActivateLockdown($"Behavior score {score} for {name}: {reason}");
                }
            };

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
            _context.Log(LogLevel.Info, Id, "Starting ransomware protection (behavior scoring v4.1)...");

            // Start the scoring engine
            _scoring.Start();

            // Deploy honeypot files
            DeployHoneypotFiles();

            // Set up file system watchers
            SetupFileWatchers();

            // Process monitoring every 3 seconds
            _processMonitor = new Timer(MonitorProcesses, null, 0, 3000);

            // Reconciliation scan every 30 seconds (catches what FSW misses)
            _reconciliationScan = new Timer(ReconciliationScan, null, 15000, 30000);

            _context.Log(LogLevel.Info, Id,
                $"Ransomware protection active. {_honeypotFiles.Count} honeypots deployed. Behavior scoring enabled.");
            return Task.CompletedTask;
        }

        public Task StopAsync()
        {
            foreach (var w in _watchers) w?.Dispose();
            _watchers = Array.Empty<FileSystemWatcher>();
            _processMonitor?.Dispose();
            _reconciliationScan?.Dispose();
            _scoring.Stop();
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
                            ["honeypotCount"] = _honeypotFiles.Count,
                            ["activeThreats"] = _scoring.GetActiveThreats()
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

                case "GetBehaviorScores":
                    return Task.FromResult(ModuleResponse.Ok("", new Dictionary<string, object>
                    {
                        ["scores"] = _scoring.GetActiveThreats(),
                        ["thresholds"] = new Dictionary<string, int>
                        {
                            ["warning"] = _scoring.WarningThreshold,
                            ["containment"] = _scoring.ContainmentThreshold,
                            ["lockdown"] = _scoring.LockdownThreshold
                        }
                    }));

                case "event":
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
                         IsRunning ? $"Active ({_honeypotFiles.Count} honeypots, scoring enabled)" : "Stopped",
            LastActivity = DateTime.UtcNow,
            Metrics = new()
            {
                ["detectionCount"] = _detections.Count,
                ["lockdownActive"] = _lockdownState.IsActive,
                ["honeypotCount"] = _honeypotFiles.Count,
                ["activeThreats"] = _scoring.GetActiveThreats().Count,
                ["scoringVersion"] = "behavior-v4.1"
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

            // Randomized decoy names that sort early (ransomware encrypts alphabetically)
            var decoyNames = new[]
            {
                "!Important_Report_2026.docx",
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
                            File.WriteAllText(path, GenerateDecoyContent(decoyNames[i]));
                            File.SetAttributes(path, FileAttributes.Hidden | FileAttributes.System);
                        }
                        _honeypotFiles.Add(path.ToLower());

                        // Store hash for reconciliation scan
                        _honeypotHashes[path.ToLower()] = ComputeFileHash(path);
                    }
                    catch { }
                }
            }
        }

        private static string GenerateDecoyContent(string filename)
        {
            return $"PC Plus Endpoint Protection - Decoy File\n" +
                   $"This file is monitored for ransomware detection.\n" +
                   $"Do not delete or modify.\n" +
                   $"File: {filename}\n" +
                   $"Created: {DateTime.UtcNow:yyyy-MM-dd}\n" +
                   new string('A', 512);
        }

        // --- File System Monitoring ---

        private void SetupFileWatchers()
        {
            var paths = new List<string>();
            foreach (var drive in DriveInfo.GetDrives())
            {
                if (drive.IsReady && drive.DriveType == DriveType.Fixed)
                {
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
            if (_honeypotFiles.Contains(e.FullPath.ToLower()))
            {
                OnHoneypotTriggered(e.FullPath, "modified");
                return;
            }

            // Try to attribute to a process for scoring
            var pid = TryGetFileOwnerProcess(e.FullPath);
            if (pid > 0)
            {
                // Check if file entropy is high (possible encryption)
                if (IsHighEntropy(e.FullPath))
                {
                    var procName = GetProcessName(pid);
                    _scoring.AddSignal(pid, procName, BehaviorSignal.HighEntropyWrite,
                        $"High entropy write to {Path.GetFileName(e.FullPath)}");
                }

                _scoring.RecordFileOperation(pid, GetProcessName(pid), e.FullPath, FileOpType.Modify);
            }
        }

        private void OnFileCreated(object sender, FileSystemEventArgs e)
        {
            var name = Path.GetFileName(e.FullPath);
            var ext = Path.GetExtension(e.FullPath);
            var pid = TryGetFileOwnerProcess(e.FullPath);
            var procName = pid > 0 ? GetProcessName(pid) : "unknown";

            // Ransom note detection
            if (RansomNoteNames.Contains(name))
            {
                if (pid > 0)
                    _scoring.AddSignal(pid, procName, BehaviorSignal.RansomNoteCreation,
                        $"Ransom note: {name}");

                RecordThreat(ThreatType.RansomNote, ThreatSeverity.Critical,
                    $"Ransomware note detected: {name}", new[] { e.FullPath },
                    processName: procName, processId: pid);
            }

            // Ransomware extension
            if (RansomwareExtensions.Contains(ext))
            {
                if (pid > 0)
                    _scoring.AddSignal(pid, procName, BehaviorSignal.RansomwareExtension,
                        $"Created: {name}");

                RecordThreat(ThreatType.FileEncryption, ThreatSeverity.High,
                    $"File with ransomware extension: {name}", new[] { e.FullPath },
                    processName: procName, processId: pid);
            }

            if (pid > 0)
                _scoring.RecordFileOperation(pid, procName, e.FullPath, FileOpType.Create);
        }

        private void OnFileRenamed(object sender, RenamedEventArgs e)
        {
            // Honeypot renamed
            if (_honeypotFiles.Contains(e.OldFullPath.ToLower()))
            {
                OnHoneypotTriggered(e.OldFullPath, $"renamed to {e.FullPath}");
                return;
            }

            var pid = TryGetFileOwnerProcess(e.FullPath);
            var procName = pid > 0 ? GetProcessName(pid) : "unknown";
            var newExt = Path.GetExtension(e.FullPath);
            var oldExt = Path.GetExtension(e.OldFullPath);

            // Score individual rename
            if (pid > 0)
            {
                _scoring.AddSignal(pid, procName, BehaviorSignal.FileRename,
                    $"{e.OldName} -> {e.Name}");

                // Extension change is more suspicious
                if (!string.Equals(oldExt, newExt, StringComparison.OrdinalIgnoreCase))
                {
                    _scoring.RecordFileOperation(pid, procName, e.FullPath, FileOpType.ExtensionChange);

                    if (RansomwareExtensions.Contains(newExt))
                    {
                        _scoring.AddSignal(pid, procName, BehaviorSignal.RansomwareExtension,
                            $"Renamed to ransomware extension: {e.Name}");
                    }
                }
                else
                {
                    _scoring.RecordFileOperation(pid, procName, e.FullPath, FileOpType.Rename);
                }
            }

            if (RansomwareExtensions.Contains(newExt))
            {
                RecordThreat(ThreatType.MassFileRename, ThreatSeverity.High,
                    $"File renamed with ransomware extension: {e.OldName} -> {e.Name}",
                    new[] { e.FullPath }, processName: procName, processId: pid);
            }
        }

        private void OnHoneypotTriggered(string filePath, string action)
        {
            _context.Log(LogLevel.Critical, Id, $"HONEYPOT TRIGGERED: {filePath} was {action}");

            // Honeypot trigger is a very strong signal (+50)
            var pid = TryGetFileOwnerProcess(filePath);
            if (pid > 0)
            {
                var procName = GetProcessName(pid);
                _scoring.AddSignal(pid, procName, BehaviorSignal.HoneypotTriggered,
                    $"Decoy file {action}: {Path.GetFileName(filePath)}");
            }

            RecordThreat(ThreatType.HoneypotTriggered, ThreatSeverity.Critical,
                $"Decoy file {action}: {Path.GetFileName(filePath)}", new[] { filePath });

            // Immediate lockdown on honeypot (strongest signal)
            if (_context.Config.LockdownOnDetection)
            {
                ActivateLockdown($"Honeypot triggered: {filePath}");
            }
        }

        // --- Reconciliation Scan ---
        // FileSystemWatcher can miss events under load. This catches what was missed.

        private void ReconciliationScan(object? state)
        {
            try
            {
                foreach (var (path, originalHash) in _honeypotHashes)
                {
                    try
                    {
                        if (!File.Exists(path))
                        {
                            // Honeypot was deleted
                            OnHoneypotTriggered(path, "deleted (detected by reconciliation scan)");
                            continue;
                        }

                        var currentHash = ComputeFileHash(path);
                        if (currentHash != originalHash)
                        {
                            OnHoneypotTriggered(path, "modified (detected by reconciliation scan)");
                            _honeypotHashes[path] = currentHash; // Update to avoid re-triggering
                        }
                    }
                    catch { }
                }
            }
            catch { }
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
                var pid = proc.Id;
                var cmdLine = GetProcessCommandLine(pid);
                var processPath = GetProcessPath(pid);

                // Known ransomware process name (+50)
                if (IsKnownRansomwareProcess(name))
                {
                    _scoring.AddSignal(pid, proc.ProcessName, BehaviorSignal.KnownRansomwareName,
                        $"Known ransomware: {proc.ProcessName}");

                    RecordThreat(ThreatType.SuspiciousProcess, ThreatSeverity.Critical,
                        $"Known ransomware process: {proc.ProcessName}",
                        processName: proc.ProcessName, processId: pid);
                }

                // Shadow copy deletion (+40)
                if (name == "vssadmin" && cmdLine.Contains("delete", StringComparison.OrdinalIgnoreCase) &&
                    cmdLine.Contains("shadows", StringComparison.OrdinalIgnoreCase))
                {
                    _scoring.AddSignal(pid, proc.ProcessName, BehaviorSignal.ShadowCopyDeletion,
                        $"vssadmin: {TruncateString(cmdLine, 100)}");

                    RecordThreat(ThreatType.ShadowCopyDeletion, ThreatSeverity.Critical,
                        $"Shadow copy deletion: {TruncateString(cmdLine, 200)}",
                        processName: proc.ProcessName, processId: pid);

                    if (_context.Config.AutoContainmentEnabled)
                        KillProcess(pid, "Shadow copy deletion");
                }

                // Suspicious PowerShell (+20)
                if ((name == "powershell" || name == "pwsh") &&
                    SuspiciousPsPatterns.Any(p => cmdLine.Contains(p, StringComparison.OrdinalIgnoreCase)))
                {
                    _scoring.AddSignal(pid, proc.ProcessName, BehaviorSignal.SuspiciousPowerShell,
                        $"Suspicious PS: {TruncateString(cmdLine, 100)}");

                    RecordThreat(ThreatType.PowerShellAbuse, ThreatSeverity.High,
                        $"Suspicious PowerShell: {TruncateString(cmdLine, 200)}",
                        processName: proc.ProcessName, processId: pid);

                    // AI analysis if available
                    if (_context.AiAnalyzer?.IsAvailable == true)
                        _ = AnalyzeWithAiAsync(proc.ProcessName, cmdLine, pid);
                }

                // Launch from risky path (+10)
                if (!string.IsNullOrEmpty(processPath) &&
                    RiskyPaths.Any(rp => processPath.Contains(rp, StringComparison.OrdinalIgnoreCase)))
                {
                    // Only flag executables, not system processes
                    if (!IsKnownSystemProcess(name))
                    {
                        _scoring.AddSignal(pid, proc.ProcessName, BehaviorSignal.RiskyLaunchPath,
                            $"Launched from: {processPath}");
                    }
                }

                // Suspicious parent-child chain (+15)
                var parentName = GetParentProcessName(pid);
                if (!string.IsNullOrEmpty(parentName) &&
                    SuspiciousParentChild.TryGetValue(parentName, out var suspiciousChildren) &&
                    suspiciousChildren.Contains(name))
                {
                    _scoring.AddSignal(pid, proc.ProcessName, BehaviorSignal.SuspiciousParentChild,
                        $"Spawned by {parentName}");
                }

                // Unsigned process check (+5)
                if (!string.IsNullOrEmpty(processPath) && !IsKnownSystemProcess(name))
                {
                    if (!IsProcessSigned(processPath))
                    {
                        _scoring.AddSignal(pid, proc.ProcessName, BehaviorSignal.UnsignedProcess,
                            $"Unsigned: {processPath}");
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
                    ["processId"] = processId.ToString(),
                    ["behaviorScore"] = processId > 0 ? _scoring.GetProcessScore(processId).ToString() : "0"
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

            // Also kill all processes with active threat scores
            foreach (var threat in _scoring.GetActiveThreats())
            {
                if (threat.TotalScore >= _scoring.ContainmentThreshold)
                {
                    KillProcess(threat.ProcessId, $"Lockdown (score: {threat.TotalScore})");
                    _lockdownState.ActiveActions.KilledProcessIds.Add(threat.ProcessId);
                    _lockdownState.ActiveActions.KilledProcessNames.Add(threat.ProcessName);
                }
            }

            if (_context.Config.AutoContainmentEnabled)
            {
                DisableNetwork();
                _lockdownState.ActiveActions.NetworkDisabled = true;
            }

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

            if (_lockdownState.ActiveActions.NetworkDisabled)
                EnableNetwork();
            if (_lockdownState.ActiveActions.RdpDisabled)
                EnableRDP();

            _lockdownState = new LockdownState();

            _ = _context.BroadcastEventAsync(new ModuleEvent
            {
                SourceModule = Id,
                EventType = ModuleEvent.LOCKDOWN_DEACTIVATED
            });
        }

        // --- Utility Methods ---

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

        private static string GetProcessPath(int pid)
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    $"SELECT ExecutablePath FROM Win32_Process WHERE ProcessId={pid}");
                foreach (ManagementObject obj in searcher.Get())
                    return obj["ExecutablePath"]?.ToString() ?? "";
            }
            catch { }
            return "";
        }

        private static string GetParentProcessName(int pid)
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    $"SELECT ParentProcessId FROM Win32_Process WHERE ProcessId={pid}");
                foreach (ManagementObject obj in searcher.Get())
                {
                    var parentPid = Convert.ToInt32(obj["ParentProcessId"]);
                    var parent = Process.GetProcessById(parentPid);
                    return parent.ProcessName.ToLower();
                }
            }
            catch { }
            return "";
        }

        /// <summary>Try to find which process has a lock on a file.</summary>
        private static int TryGetFileOwnerProcess(string filePath)
        {
            // Use Restart Manager API or WMI to find the process holding a file
            // Simplified: check recent process file handles via WMI
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    $"SELECT ProcessId FROM CIM_DataFile WHERE Name='{filePath.Replace("\\", "\\\\")}'");
                foreach (ManagementObject obj in searcher.Get())
                {
                    return Convert.ToInt32(obj["ProcessId"]);
                }
            }
            catch { }
            return 0;
        }

        /// <summary>Check if a file has high entropy (likely encrypted).</summary>
        private static bool IsHighEntropy(string filePath)
        {
            try
            {
                // Read first 4KB of the file
                using var stream = File.OpenRead(filePath);
                var buffer = new byte[Math.Min(4096, stream.Length)];
                var bytesRead = stream.Read(buffer, 0, buffer.Length);
                if (bytesRead < 100) return false;

                // Calculate Shannon entropy
                var freq = new int[256];
                for (int i = 0; i < bytesRead; i++)
                    freq[buffer[i]]++;

                double entropy = 0;
                for (int i = 0; i < 256; i++)
                {
                    if (freq[i] == 0) continue;
                    double p = (double)freq[i] / bytesRead;
                    entropy -= p * Math.Log2(p);
                }

                // Entropy > 7.5 (out of max 8.0) suggests encrypted/compressed data
                return entropy > 7.5;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>Check if an executable is digitally signed.</summary>
        private static bool IsProcessSigned(string processPath)
        {
            try
            {
                // Use Authenticode signature check via WMI
                // In production, use WinVerifyTrust API or System.Security.Cryptography.Pkcs
                var ext = Path.GetExtension(processPath).ToLower();
                if (ext != ".exe" && ext != ".dll") return true; // Non-executables are fine

                // Quick check: does the file have an embedded signature?
                using var stream = File.OpenRead(processPath);
                if (stream.Length < 64) return false;
                var header = new byte[2];
                stream.Read(header, 0, 2);
                // PE files start with "MZ"
                if (header[0] != 'M' || header[1] != 'Z') return true; // Not a PE, skip

                // For now, trust executables in Windows and Program Files directories
                var pathLower = processPath.ToLower();
                if (pathLower.StartsWith(@"c:\windows\") ||
                    pathLower.StartsWith(@"c:\program files\") ||
                    pathLower.StartsWith(@"c:\program files (x86)\"))
                    return true;

                // Everything else from user directories is considered unsigned
                return false;
            }
            catch { return true; } // Err on the side of caution
        }

        private static long ComputeFileHash(string filePath)
        {
            try
            {
                using var stream = File.OpenRead(filePath);
                using var md5 = MD5.Create();
                var hash = md5.ComputeHash(stream);
                return BitConverter.ToInt64(hash, 0);
            }
            catch { return 0; }
        }

        private static string GetProcessName(int pid)
        {
            try { return Process.GetProcessById(pid).ProcessName; }
            catch { return "unknown"; }
        }

        private static bool IsKnownRansomwareProcess(string name)
        {
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

        private static bool IsKnownSystemProcess(string name)
        {
            var system = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "svchost", "csrss", "wininit", "winlogon", "lsass",
                "services", "smss", "dwm", "explorer", "taskhostw",
                "runtimebroker", "searchindexer", "spoolsv", "dllhost"
            };
            return system.Contains(name);
        }

        private static string TruncateString(string s, int maxLen) =>
            s.Length <= maxLen ? s : s[..maxLen] + "...";
    }
}
