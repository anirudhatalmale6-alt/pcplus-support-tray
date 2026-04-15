using System.Diagnostics;
using PCPlus.Core.Interfaces;
using PCPlus.Core.Models;

namespace PCPlus.Service.Modules.Maintenance
{
    /// <summary>
    /// Automated maintenance module.
    /// Fix My Computer (one-click), temp cleanup, disk optimization,
    /// service restart, scheduled maintenance.
    /// Standard tier.
    /// </summary>
    public class MaintenanceModule : IModule
    {
        public string Id => "maintenance";
        public string Name => "Maintenance Engine";
        public string Version => "4.0.0";
        public LicenseTier RequiredTier => LicenseTier.Standard;
        public bool IsRunning { get; private set; }

        private IModuleContext _context = null!;
        private Timer? _scheduledMaintenance;
        private MaintenanceReport _lastReport = new();

        public Task InitializeAsync(IModuleContext context)
        {
            _context = context;
            return Task.CompletedTask;
        }

        public Task StartAsync(CancellationToken cancellationToken)
        {
            IsRunning = true;
            // Schedule daily maintenance at 3 AM
            var now = DateTime.Now;
            var nextRun = now.Date.AddHours(3);
            if (nextRun <= now) nextRun = nextRun.AddDays(1);
            var delay = nextRun - now;

            _scheduledMaintenance = new Timer(_ => RunScheduledMaintenance(),
                null, delay, TimeSpan.FromDays(1));

            return Task.CompletedTask;
        }

        public Task StopAsync()
        {
            _scheduledMaintenance?.Dispose();
            IsRunning = false;
            return Task.CompletedTask;
        }

        public async Task<ModuleResponse> HandleCommandAsync(ModuleCommand command)
        {
            switch (command.Action)
            {
                case "RunMaintenance":
                    var action = command.Parameters.GetValueOrDefault("action", "full");
                    var report = action switch
                    {
                        "cleanup" => RunCleanup(),
                        "fixmypc" => RunFixMyComputer(),
                        "optimize" => RunDiskOptimization(),
                        _ => RunFullMaintenance()
                    };
                    return ModuleResponse.Ok("Maintenance complete", new Dictionary<string, object>
                    {
                        ["report"] = report
                    });

                case "GetMaintenanceStatus":
                    return ModuleResponse.Ok("", new Dictionary<string, object>
                    {
                        ["lastReport"] = _lastReport
                    });

                default:
                    return ModuleResponse.Fail($"Unknown: {command.Action}");
            }
        }

        public ModuleStatus GetStatus() => new()
        {
            ModuleId = Id,
            ModuleName = Name,
            IsRunning = IsRunning,
            RequiredTier = RequiredTier,
            StatusText = IsRunning ? "Active (next: 3:00 AM)" : "Stopped",
            LastActivity = _lastReport.CompletedAt,
            Metrics = new()
            {
                ["lastCleanupMB"] = _lastReport.SpaceFreedMB,
                ["lastAction"] = _lastReport.LastAction
            }
        };

        /// <summary>"Fix My Computer" - one-click repair.</summary>
        private MaintenanceReport RunFixMyComputer()
        {
            _context.Log(LogLevel.Info, Id, "Running Fix My Computer...");
            var report = new MaintenanceReport { LastAction = "Fix My Computer" };

            // 1. Clear temp files
            report.SpaceFreedMB += ClearTempFiles();

            // 2. Flush DNS cache
            RunCmd("ipconfig", "/flushdns");
            report.Actions.Add("DNS cache flushed");

            // 3. Reset Winsock
            RunCmd("netsh", "winsock reset");
            report.Actions.Add("Winsock catalog reset");

            // 4. Run SFC (System File Checker) in background
            RunCmd("sfc", "/scannow");
            report.Actions.Add("System File Checker initiated");

            // 5. Clear Windows icon cache
            ClearIconCache();
            report.Actions.Add("Icon cache cleared");

            // 6. Restart Windows Explorer (refreshes shell)
            RestartExplorer();
            report.Actions.Add("Explorer restarted");

            report.CompletedAt = DateTime.UtcNow;
            report.Success = true;
            _lastReport = report;

            _context.Log(LogLevel.Info, Id,
                $"Fix My Computer complete: {report.Actions.Count} actions, {report.SpaceFreedMB:F0} MB freed");
            return report;
        }

        private MaintenanceReport RunCleanup()
        {
            _context.Log(LogLevel.Info, Id, "Running cleanup...");
            var report = new MaintenanceReport { LastAction = "Cleanup" };

            report.SpaceFreedMB += ClearTempFiles();
            report.SpaceFreedMB += ClearBrowserCaches();
            report.SpaceFreedMB += ClearWindowsUpdateCache();

            report.Actions.Add($"Freed {report.SpaceFreedMB:F0} MB total");
            report.CompletedAt = DateTime.UtcNow;
            report.Success = true;
            _lastReport = report;
            return report;
        }

        private MaintenanceReport RunDiskOptimization()
        {
            _context.Log(LogLevel.Info, Id, "Running disk optimization...");
            var report = new MaintenanceReport { LastAction = "Disk Optimization" };

            // Run Windows Disk Cleanup
            RunCmd("cleanmgr", "/sagerun:1");
            report.Actions.Add("Disk Cleanup initiated");

            // Optimize drives (trim/defrag)
            foreach (var drive in DriveInfo.GetDrives())
            {
                if (drive.IsReady && drive.DriveType == DriveType.Fixed)
                {
                    RunCmd("defrag", $"{drive.Name.TrimEnd('\\')} /O");
                    report.Actions.Add($"Optimized {drive.Name}");
                }
            }

            report.CompletedAt = DateTime.UtcNow;
            report.Success = true;
            _lastReport = report;
            return report;
        }

        private MaintenanceReport RunFullMaintenance()
        {
            var cleanup = RunCleanup();
            var optimize = RunDiskOptimization();
            cleanup.Actions.AddRange(optimize.Actions);
            cleanup.LastAction = "Full Maintenance";
            return cleanup;
        }

        private void RunScheduledMaintenance()
        {
            try
            {
                _context.Log(LogLevel.Info, Id, "Running scheduled maintenance (3 AM)");
                var report = RunCleanup();
                _context.Log(LogLevel.Info, Id,
                    $"Scheduled cleanup done: {report.SpaceFreedMB:F0} MB freed");
            }
            catch (Exception ex)
            {
                _context.Log(LogLevel.Error, Id, $"Scheduled maintenance error: {ex.Message}");
            }
        }

        // --- Cleanup Helpers ---

        private float ClearTempFiles()
        {
            float freed = 0;
            var tempDirs = new[]
            {
                Path.GetTempPath(),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp")
            };

            foreach (var dir in tempDirs)
            {
                freed += DeleteOldFiles(dir, TimeSpan.FromHours(24));
            }
            return freed;
        }

        private float ClearBrowserCaches()
        {
            float freed = 0;
            var localApp = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            var cacheDirs = new[]
            {
                Path.Combine(localApp, "Google", "Chrome", "User Data", "Default", "Cache"),
                Path.Combine(localApp, "Microsoft", "Edge", "User Data", "Default", "Cache"),
                Path.Combine(localApp, "Mozilla", "Firefox", "Profiles")
            };

            foreach (var dir in cacheDirs)
            {
                if (Directory.Exists(dir))
                    freed += DeleteOldFiles(dir, TimeSpan.FromDays(7));
            }
            return freed;
        }

        private float ClearWindowsUpdateCache()
        {
            float freed = 0;
            var updateDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                "SoftwareDistribution", "Download");
            if (Directory.Exists(updateDir))
                freed += DeleteOldFiles(updateDir, TimeSpan.FromDays(30));
            return freed;
        }

        private static float DeleteOldFiles(string dir, TimeSpan olderThan)
        {
            float freedMB = 0;
            try
            {
                var cutoff = DateTime.Now - olderThan;
                foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
                {
                    try
                    {
                        var fi = new FileInfo(file);
                        if (fi.LastWriteTime < cutoff)
                        {
                            freedMB += fi.Length / (1024f * 1024f);
                            fi.Delete();
                        }
                    }
                    catch { }
                }
            }
            catch { }
            return freedMB;
        }

        private static void ClearIconCache()
        {
            try
            {
                var iconCache = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "IconCache.db");
                if (File.Exists(iconCache))
                    File.Delete(iconCache);
            }
            catch { }
        }

        private static void RestartExplorer()
        {
            try
            {
                foreach (var p in Process.GetProcessesByName("explorer"))
                    p.Kill();
                // Explorer auto-restarts
            }
            catch { }
        }

        private static void RunCmd(string fileName, string arguments)
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = fileName,
                    Arguments = arguments,
                    UseShellExecute = false,
                    CreateNoWindow = true
                })?.WaitForExit(60000);
            }
            catch { }
        }
    }

    public class MaintenanceReport
    {
        public string LastAction { get; set; } = "";
        public float SpaceFreedMB { get; set; }
        public List<string> Actions { get; set; } = new();
        public bool Success { get; set; }
        public DateTime CompletedAt { get; set; }
    }
}
