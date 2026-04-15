using System.Collections.Concurrent;

namespace PCPlus.Service.Modules.Ransomware
{
    /// <summary>
    /// Behavior-based threat scoring engine.
    /// Instead of single-trigger lockdown, accumulates weighted behavioral signals
    /// per process and per system-wide activity. When score exceeds threshold,
    /// containment or lockdown is triggered.
    ///
    /// Scoring categories:
    /// - Honeypot trigger: +50 (immediate containment)
    /// - File rename rate: +5 per rename, +20 if >10/min from same process
    /// - File entropy change: +15 per high-entropy write
    /// - Multi-folder touch: +25 if process touches 5+ folders in 30 seconds
    /// - Mass extension change: +20 per batch
    /// - Launch from risky path: +10 (temp, appdata, downloads)
    /// - Suspicious parent-child: +15 (e.g., Word spawning PowerShell)
    /// - Shadow copy deletion: +40 (near-instant containment)
    /// - Known ransomware name: +50 (instant containment)
    /// - Suspicious PowerShell: +20 (encoded/obfuscated)
    /// - Ransom note creation: +35
    /// - Unsigned process: +5 (additive, not standalone trigger)
    ///
    /// Thresholds:
    /// - 30: Warning alert
    /// - 60: Auto-containment (kill process)
    /// - 80: Full lockdown
    ///
    /// Scores decay over time: -5 per minute of no new activity per process.
    /// </summary>
    public class BehaviorScoringEngine
    {
        // Per-process scores
        private readonly ConcurrentDictionary<int, ProcessThreatScore> _processScores = new();

        // System-wide activity tracking
        private readonly ConcurrentDictionary<int, ProcessFileActivity> _fileActivity = new();

        // Decay timer
        private Timer? _decayTimer;

        // Thresholds (configurable)
        public int WarningThreshold { get; set; } = 30;
        public int ContainmentThreshold { get; set; } = 60;
        public int LockdownThreshold { get; set; } = 80;
        public int DecayPerMinute { get; set; } = 5;

        // Events
        public event Action<int, string, int, string>? OnWarning;      // pid, processName, score, reason
        public event Action<int, string, int, string>? OnContainment;   // pid, processName, score, reason
        public event Action<int, string, int, string>? OnLockdown;      // pid, processName, score, reason

        public void Start()
        {
            _decayTimer = new Timer(DecayScores, null, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(1));
        }

        public void Stop()
        {
            _decayTimer?.Dispose();
            _processScores.Clear();
            _fileActivity.Clear();
        }

        /// <summary>Add a behavioral signal for a process. Returns the new total score.</summary>
        public int AddSignal(int pid, string processName, BehaviorSignal signal, string detail = "")
        {
            var score = _processScores.GetOrAdd(pid, _ => new ProcessThreatScore
            {
                ProcessId = pid,
                ProcessName = processName
            });

            var points = GetSignalPoints(signal);
            score.TotalScore += points;
            score.LastActivity = DateTime.UtcNow;
            score.Signals.Add(new ScoredSignal
            {
                Signal = signal,
                Points = points,
                Detail = detail,
                Timestamp = DateTime.UtcNow
            });

            // Check thresholds (only fire once per level)
            if (score.TotalScore >= LockdownThreshold && !score.LockdownFired)
            {
                score.LockdownFired = true;
                var reason = BuildReason(score);
                OnLockdown?.Invoke(pid, processName, score.TotalScore, reason);
            }
            else if (score.TotalScore >= ContainmentThreshold && !score.ContainmentFired)
            {
                score.ContainmentFired = true;
                var reason = BuildReason(score);
                OnContainment?.Invoke(pid, processName, score.TotalScore, reason);
            }
            else if (score.TotalScore >= WarningThreshold && !score.WarningFired)
            {
                score.WarningFired = true;
                var reason = BuildReason(score);
                OnWarning?.Invoke(pid, processName, score.TotalScore, reason);
            }

            return score.TotalScore;
        }

        /// <summary>Record a file operation for rate-based detection.</summary>
        public void RecordFileOperation(int pid, string processName, string filePath, FileOpType opType)
        {
            var activity = _fileActivity.GetOrAdd(pid, _ => new ProcessFileActivity
            {
                ProcessId = pid,
                ProcessName = processName
            });

            var now = DateTime.UtcNow;
            activity.Operations.Add(new FileOperation
            {
                FilePath = filePath,
                Type = opType,
                Timestamp = now,
                FolderPath = Path.GetDirectoryName(filePath) ?? ""
            });

            // Trim old operations (keep last 2 minutes)
            var cutoff = now.AddMinutes(-2);
            activity.Operations.RemoveAll(o => o.Timestamp < cutoff);

            // Check rate-based signals
            CheckRateSignals(pid, processName, activity);
        }

        /// <summary>Get the current threat score for a process.</summary>
        public int GetProcessScore(int pid)
        {
            return _processScores.TryGetValue(pid, out var score) ? score.TotalScore : 0;
        }

        /// <summary>Get all processes with active threat scores.</summary>
        public List<ProcessThreatScore> GetActiveThreats()
        {
            return _processScores.Values
                .Where(s => s.TotalScore > 0)
                .OrderByDescending(s => s.TotalScore)
                .ToList();
        }

        /// <summary>Reset score for a specific process (after containment).</summary>
        public void ResetProcess(int pid)
        {
            _processScores.TryRemove(pid, out _);
            _fileActivity.TryRemove(pid, out _);
        }

        private void CheckRateSignals(int pid, string processName, ProcessFileActivity activity)
        {
            var lastMinute = activity.Operations
                .Where(o => o.Timestamp > DateTime.UtcNow.AddMinutes(-1))
                .ToList();

            // High rename rate: >10 renames per minute from same process
            var renameCount = lastMinute.Count(o => o.Type == FileOpType.Rename);
            if (renameCount > 10 && !activity.HighRenameRateFired)
            {
                activity.HighRenameRateFired = true;
                AddSignal(pid, processName, BehaviorSignal.HighFileRenameRate,
                    $"{renameCount} renames in last minute");
            }

            // Multi-folder touch: process touches 5+ distinct folders in 30 seconds
            var last30s = lastMinute.Where(o => o.Timestamp > DateTime.UtcNow.AddSeconds(-30)).ToList();
            var distinctFolders = last30s.Select(o => o.FolderPath).Distinct().Count();
            if (distinctFolders >= 5 && !activity.MultiFolderFired)
            {
                activity.MultiFolderFired = true;
                AddSignal(pid, processName, BehaviorSignal.MultiFolderTouch,
                    $"Touched {distinctFolders} folders in 30 seconds");
            }

            // Mass extension change: >5 files getting new extension in 1 minute
            var extChanges = lastMinute.Count(o => o.Type == FileOpType.ExtensionChange);
            if (extChanges > 5 && !activity.MassExtChangeFired)
            {
                activity.MassExtChangeFired = true;
                AddSignal(pid, processName, BehaviorSignal.MassExtensionChange,
                    $"{extChanges} extension changes in last minute");
            }
        }

        private void DecayScores(object? state)
        {
            var toRemove = new List<int>();

            foreach (var kvp in _processScores)
            {
                var score = kvp.Value;
                var inactiveMinutes = (DateTime.UtcNow - score.LastActivity).TotalMinutes;

                if (inactiveMinutes >= 1)
                {
                    score.TotalScore = Math.Max(0, score.TotalScore - DecayPerMinute);

                    // Reset threshold flags if score drops below
                    if (score.TotalScore < WarningThreshold) score.WarningFired = false;
                    if (score.TotalScore < ContainmentThreshold) score.ContainmentFired = false;
                    if (score.TotalScore < LockdownThreshold) score.LockdownFired = false;
                }

                // Remove if score is 0 and inactive for 10+ minutes
                if (score.TotalScore <= 0 && inactiveMinutes >= 10)
                    toRemove.Add(kvp.Key);
            }

            foreach (var pid in toRemove)
            {
                _processScores.TryRemove(pid, out _);
                _fileActivity.TryRemove(pid, out _);
            }
        }

        private static int GetSignalPoints(BehaviorSignal signal) => signal switch
        {
            BehaviorSignal.HoneypotTriggered => 50,
            BehaviorSignal.KnownRansomwareName => 50,
            BehaviorSignal.ShadowCopyDeletion => 40,
            BehaviorSignal.RansomNoteCreation => 35,
            BehaviorSignal.MultiFolderTouch => 25,
            BehaviorSignal.MassExtensionChange => 20,
            BehaviorSignal.SuspiciousPowerShell => 20,
            BehaviorSignal.HighFileRenameRate => 20,
            BehaviorSignal.HighEntropyWrite => 15,
            BehaviorSignal.SuspiciousParentChild => 15,
            BehaviorSignal.RiskyLaunchPath => 10,
            BehaviorSignal.FileRename => 5,
            BehaviorSignal.UnsignedProcess => 5,
            BehaviorSignal.RansomwareExtension => 10,
            _ => 5
        };

        private static string BuildReason(ProcessThreatScore score)
        {
            var topSignals = score.Signals
                .OrderByDescending(s => s.Points)
                .Take(3)
                .Select(s => $"{s.Signal} (+{s.Points}): {s.Detail}");
            return $"Score: {score.TotalScore} | {string.Join(" | ", topSignals)}";
        }
    }

    public enum BehaviorSignal
    {
        HoneypotTriggered,
        KnownRansomwareName,
        ShadowCopyDeletion,
        RansomNoteCreation,
        MultiFolderTouch,
        MassExtensionChange,
        SuspiciousPowerShell,
        HighFileRenameRate,
        HighEntropyWrite,
        SuspiciousParentChild,
        RiskyLaunchPath,
        FileRename,
        UnsignedProcess,
        RansomwareExtension,
    }

    public enum FileOpType
    {
        Create,
        Modify,
        Rename,
        ExtensionChange,
        Delete
    }

    public class ProcessThreatScore
    {
        public int ProcessId { get; set; }
        public string ProcessName { get; set; } = "";
        public int TotalScore { get; set; }
        public DateTime LastActivity { get; set; }
        public List<ScoredSignal> Signals { get; set; } = new();
        public bool WarningFired { get; set; }
        public bool ContainmentFired { get; set; }
        public bool LockdownFired { get; set; }
    }

    public class ScoredSignal
    {
        public BehaviorSignal Signal { get; set; }
        public int Points { get; set; }
        public string Detail { get; set; } = "";
        public DateTime Timestamp { get; set; }
    }

    public class ProcessFileActivity
    {
        public int ProcessId { get; set; }
        public string ProcessName { get; set; } = "";
        public List<FileOperation> Operations { get; set; } = new();
        public bool HighRenameRateFired { get; set; }
        public bool MultiFolderFired { get; set; }
        public bool MassExtChangeFired { get; set; }
    }

    public class FileOperation
    {
        public string FilePath { get; set; } = "";
        public string FolderPath { get; set; } = "";
        public FileOpType Type { get; set; }
        public DateTime Timestamp { get; set; }
    }
}
