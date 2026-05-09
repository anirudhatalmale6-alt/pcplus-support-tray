using System.Diagnostics;
using PCPlus.Core.Interfaces;

namespace PCPlus.Service.Engine
{
    public class TrayWatchdog : IDisposable
    {
        private readonly ServiceConfig _config;
        private readonly ModuleEngine _engine;
        private Timer? _watchTimer;
        private bool _disposed;
        private int _consecutiveRestarts;
        private DateTime _lastRestart = DateTime.MinValue;

        private const int CHECK_INTERVAL_SECONDS = 60;
        private const int MAX_RESTARTS_PER_HOUR = 5;
        private const string TRAY_PROCESS_NAME = "PCPlusTray";

        public TrayWatchdog(ServiceConfig config, ModuleEngine engine)
        {
            _config = config;
            _engine = engine;
        }

        public void Start()
        {
            var enabled = _config.GetValue("trayWatchdogEnabled")?.ToLower() != "false";
            if (!enabled)
            {
                _engine.Log(LogLevel.Info, "tray-watchdog", "Tray watchdog disabled by config");
                return;
            }

            _watchTimer = new Timer(_ => CheckAndRestart(),
                null, TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(CHECK_INTERVAL_SECONDS));

            _engine.Log(LogLevel.Info, "tray-watchdog",
                $"Tray watchdog started (check every {CHECK_INTERVAL_SECONDS}s)");
        }

        private void CheckAndRestart()
        {
            try
            {
                var trayProcesses = Process.GetProcessesByName(TRAY_PROCESS_NAME);
                if (trayProcesses.Length > 0)
                {
                    foreach (var p in trayProcesses) p.Dispose();
                    if (_consecutiveRestarts > 0)
                    {
                        _consecutiveRestarts = 0;
                        _engine.Log(LogLevel.Info, "tray-watchdog", "Tray app recovered and running");
                    }
                    return;
                }

                if ((DateTime.UtcNow - _lastRestart).TotalHours >= 1)
                    _consecutiveRestarts = 0;

                if (_consecutiveRestarts >= MAX_RESTARTS_PER_HOUR)
                {
                    _engine.Log(LogLevel.Warning, "tray-watchdog",
                        $"Tray crashed {MAX_RESTARTS_PER_HOUR} times in the last hour - backing off");
                    return;
                }

                var trayExe = FindTrayExe();
                if (trayExe == null)
                {
                    _engine.Log(LogLevel.Warning, "tray-watchdog", "Cannot find PCPlusTray.exe");
                    return;
                }

                if (!HasActiveUserSession())
                    return;

                _engine.Log(LogLevel.Info, "tray-watchdog", "Tray app not running - restarting...");

                var psi = new ProcessStartInfo
                {
                    FileName = trayExe,
                    UseShellExecute = true,
                    WindowStyle = ProcessWindowStyle.Hidden
                };
                Process.Start(psi);

                _consecutiveRestarts++;
                _lastRestart = DateTime.UtcNow;

                _engine.Log(LogLevel.Info, "tray-watchdog",
                    $"Tray app restarted from {trayExe} (restart #{_consecutiveRestarts})");
            }
            catch (Exception ex)
            {
                _engine.Log(LogLevel.Warning, "tray-watchdog", $"Watchdog check failed: {ex.Message}");
            }
        }

        private string? FindTrayExe()
        {
            var serviceDir = Path.GetDirectoryName(Environment.ProcessPath)
                ?? Path.GetDirectoryName(typeof(TrayWatchdog).Assembly.Location);

            if (serviceDir == null) return null;

            var installRoot = Directory.GetParent(serviceDir)?.FullName ?? serviceDir;

            var candidates = new[]
            {
                Path.Combine(installRoot, "Tray", "PCPlusTray.exe"),
                Path.Combine(installRoot, "PCPlusTray.exe"),
                Path.Combine(serviceDir, "PCPlusTray.exe"),
            };

            return candidates.FirstOrDefault(File.Exists);
        }

        private static bool HasActiveUserSession()
        {
            try
            {
                var explorer = Process.GetProcessesByName("explorer");
                var hasSession = explorer.Length > 0;
                foreach (var p in explorer) p.Dispose();
                return hasSession;
            }
            catch { return true; }
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            _watchTimer?.Dispose();
        }
    }
}
