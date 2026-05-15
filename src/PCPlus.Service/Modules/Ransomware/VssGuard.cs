using System.Diagnostics;
using System.Management;
using System.Security.AccessControl;
using System.Security.Principal;
using PCPlus.Core.Interfaces;

namespace PCPlus.Service.Modules.Ransomware
{
    /// <summary>
    /// Volume Shadow Copy (VSS) Guard - Active protection layer.
    /// Instead of just detecting shadow copy deletion, this PREVENTS it:
    ///
    /// 1. Process Interception: WMI event subscription watches for vssadmin.exe,
    ///    wmic.exe, and PowerShell spawning with shadow-delete args. Kills within
    ///    milliseconds before the delete command can execute.
    /// 2. Scheduled VSS Snapshots: Creates system restore points on a schedule
    ///    so even if something gets through, there are recent recovery points.
    /// 3. BCDEdit Protection: Monitors for boot config changes (ransomware disables
    ///    safe mode, recovery, etc.)
    /// 4. Safe Process Whitelist: Only our service and Windows Update can legitimately
    ///    touch shadow copies.
    /// </summary>
    public class VssGuard : IDisposable
    {
        private ManagementEventWatcher? _processWatcher;
        private Timer? _snapshotTimer;
        private Timer? _integrityTimer;
        private IModuleContext _context = null!;
        private readonly BehaviorScoringEngine _scoring;
        private bool _isActive;
        private int _blockedAttempts;
        private int _snapshotCount;
        private DateTime _lastSnapshotTime = DateTime.MinValue;
        private readonly List<VssEvent> _events = new();
        private readonly object _lock = new();

        // Processes that legitimately interact with VSS
        private static readonly HashSet<string> WhitelistedParents = new(StringComparer.OrdinalIgnoreCase)
        {
            "pcplusservice", "pcplusendpoint", "svchost", "tiworker",
            "trustedinstaller", "msiexec", "wuauclt", "usoclient"
        };

        // Commands that target shadow copies
        private static readonly (string process, string[] patterns)[] DangerousCommands = new[]
        {
            ("vssadmin", new[] { "delete shadows", "resize shadowstorage /for=", "delete shadowstorage" }),
            ("wmic", new[] { "shadowcopy delete", "shadowcopy where", "shadowcopy call create" }),
            ("powershell", new[] { "get-wmiobject win32_shadowcopy", "delete()", "win32_shadowcopy", "remove-wmiobject" }),
            ("pwsh", new[] { "get-wmiobject win32_shadowcopy", "delete()", "win32_shadowcopy", "remove-wmiobject" }),
            ("cmd", new[] { "vssadmin delete", "wmic shadowcopy" }),
            ("bcdedit", new[] { "/set", "recoveryenabled no", "bootstatuspolicy ignoreallfailures", "safeboot" }),
            ("wbadmin", new[] { "delete catalog", "delete systemstatebackup" }),
        };

        public VssGuard(BehaviorScoringEngine scoring)
        {
            _scoring = scoring;
        }

        public void Start(IModuleContext context)
        {
            _context = context;
            _isActive = true;

            StartProcessInterception();
            StartSnapshotSchedule();
            StartIntegrityMonitor();

            _context.Log(LogLevel.Info, "ransomware", "VSS Guard active: shadow copy protection, process interception, snapshot scheduling");
        }

        public void Stop()
        {
            _isActive = false;
            _processWatcher?.Stop();
            _processWatcher?.Dispose();
            _snapshotTimer?.Dispose();
            _integrityTimer?.Dispose();
        }

        public VssGuardStatus GetStatus()
        {
            return new VssGuardStatus
            {
                IsActive = _isActive,
                BlockedAttempts = _blockedAttempts,
                SnapshotCount = _snapshotCount,
                LastSnapshotTime = _lastSnapshotTime,
                RecentEvents = _events.TakeLast(20).Reverse().ToList()
            };
        }

        #region Process Interception

        private void StartProcessInterception()
        {
            try
            {
                // WMI event subscription: fires when ANY new process is created
                // This catches vssadmin/wmic/bcdedit within milliseconds of launch
                var query = new WqlEventQuery(
                    "__InstanceCreationEvent",
                    TimeSpan.FromMilliseconds(100),  // Poll every 100ms for near-instant detection
                    "TargetInstance ISA 'Win32_Process'");

                _processWatcher = new ManagementEventWatcher(query);
                _processWatcher.EventArrived += OnProcessCreated;
                _processWatcher.Start();

                _context.Log(LogLevel.Info, "ransomware", "VSS Guard: Process interception active (100ms polling)");
            }
            catch (Exception ex)
            {
                _context.Log(LogLevel.Error, "ransomware", $"VSS Guard: Failed to start process interception: {ex.Message}");
            }
        }

        private void OnProcessCreated(object sender, EventArrivedEventArgs e)
        {
            try
            {
                var targetInstance = (ManagementBaseObject)e.NewEvent["TargetInstance"];
                var processName = targetInstance["Name"]?.ToString()?.ToLower() ?? "";
                var commandLine = targetInstance["CommandLine"]?.ToString() ?? "";
                var pid = Convert.ToInt32(targetInstance["ProcessId"]);
                var parentPid = Convert.ToInt32(targetInstance["ParentProcessId"]);

                var baseName = Path.GetFileNameWithoutExtension(processName);

                foreach (var (dangerousProc, patterns) in DangerousCommands)
                {
                    if (!baseName.Equals(dangerousProc, StringComparison.OrdinalIgnoreCase))
                        continue;

                    foreach (var pattern in patterns)
                    {
                        if (!commandLine.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                            continue;

                        // Check if parent is whitelisted
                        var parentName = GetProcessName(parentPid);
                        if (WhitelistedParents.Contains(parentName))
                            continue;

                        // BLOCK IT - kill immediately
                        KillProcessImmediate(pid, processName);
                        _blockedAttempts++;

                        var detail = $"BLOCKED {processName} (PID {pid}, parent: {parentName}): {Truncate(commandLine, 150)}";
                        _context.Log(LogLevel.Critical, "ransomware", $"VSS Guard: {detail}");

                        _scoring.AddSignal(parentPid > 0 ? parentPid : pid,
                            parentPid > 0 ? parentName : processName,
                            BehaviorSignal.ShadowCopyDeletion,
                            $"Attempted: {Truncate(commandLine, 100)}");

                        RecordEvent("blocked", processName, detail);

                        _context.RaiseAlert(new PCPlus.Core.Models.Alert
                        {
                            ModuleId = "ransomware",
                            Title = "Shadow Copy Attack Blocked",
                            Message = $"Blocked {processName} from executing: {Truncate(commandLine, 200)}\n" +
                                      $"Parent process: {parentName} (PID {parentPid})",
                            Severity = PCPlus.Core.Models.AlertSeverity.Emergency,
                            Category = "ransomware",
                            Metadata = new()
                            {
                                ["action"] = "blocked",
                                ["process"] = processName,
                                ["commandLine"] = Truncate(commandLine, 500),
                                ["parentProcess"] = parentName,
                                ["parentPid"] = parentPid.ToString()
                            }
                        });

                        return;
                    }
                }
            }
            catch { }
        }

        private static void KillProcessImmediate(int pid, string name)
        {
            try
            {
                var proc = Process.GetProcessById(pid);
                proc.Kill(entireProcessTree: true);
            }
            catch { }

            // Belt-and-suspenders: also use taskkill for reliability
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "taskkill",
                    Arguments = $"/F /PID {pid} /T",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true
                };
                using var p = Process.Start(psi);
                p?.WaitForExit(3000);
            }
            catch { }
        }

        #endregion

        #region Scheduled VSS Snapshots

        private void StartSnapshotSchedule()
        {
            // Create a VSS snapshot every 4 hours as insurance
            _snapshotTimer = new Timer(CreateSnapshot, null, TimeSpan.FromMinutes(5), TimeSpan.FromHours(4));
        }

        private void CreateSnapshot(object? state)
        {
            try
            {
                // Create a system restore point via WMI
                var scope = new ManagementScope(@"\\.\root\default");
                var path = new ManagementPath("SystemRestore");
                var options = new ObjectGetOptions();

                using var restoreClass = new ManagementClass(scope, path, options);
                var inParams = restoreClass.GetMethodParameters("CreateRestorePoint");
                inParams["Description"] = $"PCPlus Auto-Protect {DateTime.Now:yyyy-MM-dd HH:mm}";
                inParams["RestorePointType"] = 12; // APPLICATION_INSTALL
                inParams["EventType"] = 100; // BEGIN_SYSTEM_CHANGE

                var outParams = restoreClass.InvokeMethod("CreateRestorePoint", inParams, null);
                var returnValue = Convert.ToInt32(outParams["ReturnValue"]);

                if (returnValue == 0)
                {
                    _snapshotCount++;
                    _lastSnapshotTime = DateTime.UtcNow;
                    _context.Log(LogLevel.Info, "ransomware", $"VSS Guard: System restore point created (#{_snapshotCount})");
                    RecordEvent("snapshot_created", "system", $"Auto-protect restore point #{_snapshotCount}");
                }
                else
                {
                    _context.Log(LogLevel.Warning, "ransomware", $"VSS Guard: Restore point creation returned {returnValue}");
                }
            }
            catch (Exception ex)
            {
                _context.Log(LogLevel.Warning, "ransomware", $"VSS Guard: Snapshot failed: {ex.Message}");
            }
        }

        /// <summary>Force-create a snapshot right now (triggered by threat detection).</summary>
        public void CreateEmergencySnapshot()
        {
            _context.Log(LogLevel.Warning, "ransomware", "VSS Guard: Creating emergency snapshot due to threat detection");
            CreateSnapshot(null);
        }

        #endregion

        #region Integrity Monitor

        private void StartIntegrityMonitor()
        {
            // Every 2 minutes, verify shadow copies still exist
            _integrityTimer = new Timer(CheckShadowCopyIntegrity, null, TimeSpan.FromMinutes(2), TimeSpan.FromMinutes(2));
        }

        private void CheckShadowCopyIntegrity(object? state)
        {
            try
            {
                int count = 0;
                using var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_ShadowCopy");
                foreach (ManagementObject obj in searcher.Get())
                {
                    count++;
                    obj.Dispose();
                }

                if (count == 0 && _snapshotCount > 0)
                {
                    // All shadow copies were deleted outside our control
                    _context.Log(LogLevel.Critical, "ransomware",
                        "VSS Guard: ALL shadow copies deleted! Possible ransomware activity.");

                    _context.RaiseAlert(new PCPlus.Core.Models.Alert
                    {
                        ModuleId = "ransomware",
                        Title = "All Shadow Copies Deleted",
                        Message = "All Volume Shadow Copies have been removed. This is a strong indicator of ransomware activity. Creating emergency restore point.",
                        Severity = PCPlus.Core.Models.AlertSeverity.Emergency,
                        Category = "ransomware"
                    });

                    RecordEvent("shadow_copies_wiped", "system", "All shadow copies deleted - possible ransomware");
                    CreateEmergencySnapshot();
                }
            }
            catch { }
        }

        #endregion

        #region Event Tracking

        private void RecordEvent(string type, string process, string detail)
        {
            lock (_lock)
            {
                _events.Add(new VssEvent
                {
                    Type = type,
                    Process = process,
                    Detail = detail,
                    Timestamp = DateTime.UtcNow
                });
                if (_events.Count > 1000)
                    _events.RemoveRange(0, _events.Count - 500);
            }
        }

        #endregion

        private static string GetProcessName(int pid)
        {
            try { return Process.GetProcessById(pid).ProcessName.ToLower(); }
            catch { return "unknown"; }
        }

        private static string Truncate(string s, int max) =>
            s.Length <= max ? s : s[..max] + "...";

        public void Dispose()
        {
            Stop();
        }
    }

    public class VssGuardStatus
    {
        public bool IsActive { get; set; }
        public int BlockedAttempts { get; set; }
        public int SnapshotCount { get; set; }
        public DateTime LastSnapshotTime { get; set; }
        public List<VssEvent> RecentEvents { get; set; } = new();
    }

    public class VssEvent
    {
        public string Type { get; set; } = "";
        public string Process { get; set; } = "";
        public string Detail { get; set; } = "";
        public DateTime Timestamp { get; set; }
    }
}
