using System.Collections.Concurrent;
using PCPlus.Core.Interfaces;

namespace PCPlus.Service.Modules.Ransomware
{
    /// <summary>
    /// Behavior-based threat scoring engine with configurable weights.
    /// All signal weights and thresholds are read from IServiceConfig,
    /// allowing per-deployment tuning via config.json or central dashboard push.
    ///
    /// Scores decay over time: configurable per minute of no new activity per process.
    /// </summary>
    public class BehaviorScoringEngine
    {
        private readonly ConcurrentDictionary<int, ProcessThreatScore> _processScores = new();
        private readonly ConcurrentDictionary<int, ProcessFileActivity> _fileActivity = new();
        private Timer? _decayTimer;
        private IServiceConfig? _config;

        // Fallback defaults (used if config not set)
        private static readonly Dictionary<BehaviorSignal, int> DefaultWeights = new()
        {
            [BehaviorSignal.HoneypotTriggered] = 50,
            [BehaviorSignal.KnownRansomwareName] = 50,
            [BehaviorSignal.ShadowCopyDeletion] = 40,
            [BehaviorSignal.RansomNoteCreation] = 35,
            [BehaviorSignal.MultiFolderTouch] = 25,
            [BehaviorSignal.MassExtensionChange] = 20,
            [BehaviorSignal.SuspiciousPowerShell] = 20,
            [BehaviorSignal.HighFileRenameRate] = 20,
            [BehaviorSignal.HighEntropyWrite] = 15,
            [BehaviorSignal.SuspiciousParentChild] = 15,
            [BehaviorSignal.RiskyLaunchPath] = 10,
            [BehaviorSignal.RansomwareExtension] = 10,
            [BehaviorSignal.FileRename] = 5,
            [BehaviorSignal.UnsignedProcess] = 5,
        };

        // Thresholds - read from config
        public int WarningThreshold => _config?.ScoringWarningThreshold ?? 30;
        public int ContainmentThreshold => _config?.ScoringContainmentThreshold ?? 60;
        public int LockdownThreshold => _config?.ScoringLockdownThreshold ?? 80;
        public int DecayPerMinute => _config?.ScoringDecayPerMinute ?? 5;

        // Events
        public event Action<int, string, int, string>? OnWarning;
        public event Action<int, string, int, string>? OnContainment;
        public event Action<int, string, int, string>? OnLockdown;

        /// <summary>Initialize with config for configurable weights.</summary>
        public void Initialize(IServiceConfig config)
        {
            _config = config;
        }

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
                OnLockdown?.Invoke(pid, processName, score.TotalScore, BuildReason(score));
            }
            else if (score.TotalScore >= ContainmentThreshold && !score.ContainmentFired)
            {
                score.ContainmentFired = true;
                OnContainment?.Invoke(pid, processName, score.TotalScore, BuildReason(score));
            }
            else if (score.TotalScore >= WarningThreshold && !score.WarningFired)
            {
                score.WarningFired = true;
                OnWarning?.Invoke(pid, processName, score.TotalScore, BuildReason(score));
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

            var cutoff = now.AddMinutes(-2);
            activity.Operations.RemoveAll(o => o.Timestamp < cutoff);

            CheckRateSignals(pid, processName, activity);
        }

        public int GetProcessScore(int pid)
        {
            return _processScores.TryGetValue(pid, out var score) ? score.TotalScore : 0;
        }

        public List<ProcessThreatScore> GetActiveThreats()
        {
            return _processScores.Values
                .Where(s => s.TotalScore > 0)
                .OrderByDescending(s => s.TotalScore)
                .ToList();
        }

        /// <summary>Get current scoring configuration (weights + thresholds) for dashboard display.</summary>
        public Dictionary<string, int> GetScoringConfig()
        {
            var config = new Dictionary<string, int>();
            foreach (BehaviorSignal signal in Enum.GetValues<BehaviorSignal>())
            {
                config[$"weight.{signal}"] = GetSignalPoints(signal);
            }
            config["threshold.warning"] = WarningThreshold;
            config["threshold.containment"] = ContainmentThreshold;
            config["threshold.lockdown"] = LockdownThreshold;
            config["decay.perMinute"] = DecayPerMinute;
            return config;
        }

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

            var renameCount = lastMinute.Count(o => o.Type == FileOpType.Rename);
            if (renameCount > 10 && !activity.HighRenameRateFired)
            {
                activity.HighRenameRateFired = true;
                AddSignal(pid, processName, BehaviorSignal.HighFileRenameRate,
                    $"{renameCount} renames in last minute");
            }

            var last30s = lastMinute.Where(o => o.Timestamp > DateTime.UtcNow.AddSeconds(-30)).ToList();
            var distinctFolders = last30s.Select(o => o.FolderPath).Distinct().Count();
            if (distinctFolders >= 5 && !activity.MultiFolderFired)
            {
                activity.MultiFolderFired = true;
                AddSignal(pid, processName, BehaviorSignal.MultiFolderTouch,
                    $"Touched {distinctFolders} folders in 30 seconds");
            }

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
                    if (score.TotalScore < WarningThreshold) score.WarningFired = false;
                    if (score.TotalScore < ContainmentThreshold) score.ContainmentFired = false;
                    if (score.TotalScore < LockdownThreshold) score.LockdownFired = false;
                }

                if (score.TotalScore <= 0 && inactiveMinutes >= 10)
                    toRemove.Add(kvp.Key);
            }

            foreach (var pid in toRemove)
            {
                _processScores.TryRemove(pid, out _);
                _fileActivity.TryRemove(pid, out _);
            }
        }

        /// <summary>Get signal points from config or defaults.</summary>
        private int GetSignalPoints(BehaviorSignal signal)
        {
            if (_config == null)
                return DefaultWeights.TryGetValue(signal, out var d) ? d : 5;

            return signal switch
            {
                BehaviorSignal.HoneypotTriggered => _config.ScoreHoneypotTriggered,
                BehaviorSignal.KnownRansomwareName => _config.ScoreKnownRansomware,
                BehaviorSignal.ShadowCopyDeletion => _config.ScoreShadowCopyDeletion,
                BehaviorSignal.RansomNoteCreation => _config.ScoreRansomNoteCreation,
                BehaviorSignal.MultiFolderTouch => _config.ScoreMultiFolderTouch,
                BehaviorSignal.MassExtensionChange => _config.ScoreMassExtensionChange,
                BehaviorSignal.SuspiciousPowerShell => _config.ScoreSuspiciousPowerShell,
                BehaviorSignal.HighFileRenameRate => _config.ScoreHighFileRenameRate,
                BehaviorSignal.HighEntropyWrite => _config.ScoreHighEntropyWrite,
                BehaviorSignal.SuspiciousParentChild => _config.ScoreSuspiciousParentChild,
                BehaviorSignal.RiskyLaunchPath => _config.ScoreRiskyLaunchPath,
                BehaviorSignal.RansomwareExtension => _config.ScoreRansomwareExtension,
                BehaviorSignal.FileRename => _config.ScoreFileRename,
                BehaviorSignal.UnsignedProcess => _config.ScoreUnsignedProcess,
                _ => 5
            };
        }

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
