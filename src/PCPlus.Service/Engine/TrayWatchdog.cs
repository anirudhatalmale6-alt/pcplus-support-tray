using System.Diagnostics;
using System.Runtime.InteropServices;
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

            EnsureStartupRegistryKey();

            _watchTimer = new Timer(_ => CheckAndRestart(),
                null, TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(CHECK_INTERVAL_SECONDS));

            _engine.Log(LogLevel.Info, "tray-watchdog",
                $"Tray watchdog started (check every {CHECK_INTERVAL_SECONDS}s)");
        }

        private void EnsureStartupRegistryKey()
        {
            try
            {
                var trayExe = FindTrayExe();
                if (trayExe == null) return;

                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", true);
                if (key != null)
                {
                    var existing = key.GetValue("PCPlusEndpoint") as string;
                    if (existing != $"\"{trayExe}\"")
                    {
                        key.SetValue("PCPlusEndpoint", $"\"{trayExe}\"");
                        _engine.Log(LogLevel.Info, "tray-watchdog", "Registered tray app for auto-start on login");
                    }
                }
            }
            catch (Exception ex)
            {
                _engine.Log(LogLevel.Warning, "tray-watchdog", $"Failed to set startup registry: {ex.Message}");
            }
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

                if (LaunchInUserSession(trayExe))
                {
                    _consecutiveRestarts++;
                    _lastRestart = DateTime.UtcNow;
                    _engine.Log(LogLevel.Info, "tray-watchdog",
                        $"Tray app restarted in user session (restart #{_consecutiveRestarts})");
                }
                else
                {
                    _engine.Log(LogLevel.Warning, "tray-watchdog", "Failed to launch tray in user session");
                }
            }
            catch (Exception ex)
            {
                _engine.Log(LogLevel.Warning, "tray-watchdog", $"Watchdog check failed: {ex.Message}");
            }
        }

        private bool LaunchInUserSession(string trayExe)
        {
            var sessionId = WTSGetActiveConsoleSessionId();
            if (sessionId == 0xFFFFFFFF)
                return false;

            IntPtr userToken = IntPtr.Zero;
            IntPtr dupToken = IntPtr.Zero;

            try
            {
                if (!WTSQueryUserToken(sessionId, out userToken))
                    return false;

                var sa = new SECURITY_ATTRIBUTES();
                sa.nLength = Marshal.SizeOf(sa);

                if (!DuplicateTokenEx(userToken, 0x10000000, ref sa,
                    SECURITY_IMPERSONATION_LEVEL.SecurityIdentification,
                    TOKEN_TYPE.TokenPrimary, out dupToken))
                    return false;

                var si = new STARTUPINFO();
                si.cb = Marshal.SizeOf(si);
                si.lpDesktop = @"winsta0\default";

                var pi = new PROCESS_INFORMATION();

                var env = IntPtr.Zero;
                CreateEnvironmentBlock(out env, dupToken, false);

                var result = CreateProcessAsUser(
                    dupToken,
                    trayExe,
                    null,
                    ref sa, ref sa,
                    false,
                    0x00000010 | 0x00000400, // NORMAL_PRIORITY | CREATE_UNICODE_ENVIRONMENT
                    env,
                    Path.GetDirectoryName(trayExe),
                    ref si, out pi);

                if (env != IntPtr.Zero)
                    DestroyEnvironmentBlock(env);

                if (result)
                {
                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);
                    return true;
                }

                return false;
            }
            finally
            {
                if (userToken != IntPtr.Zero) CloseHandle(userToken);
                if (dupToken != IntPtr.Zero) CloseHandle(dupToken);
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

        #region Win32 Interop

        [DllImport("kernel32.dll")]
        private static extern uint WTSGetActiveConsoleSessionId();

        [DllImport("wtsapi32.dll", SetLastError = true)]
        private static extern bool WTSQueryUserToken(uint sessionId, out IntPtr phToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess,
            ref SECURITY_ATTRIBUTES lpTokenAttributes, SECURITY_IMPERSONATION_LEVEL impersonationLevel,
            TOKEN_TYPE tokenType, out IntPtr phNewToken);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CreateProcessAsUser(IntPtr hToken, string? lpApplicationName,
            string? lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes,
            ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles,
            uint dwCreationFlags, IntPtr lpEnvironment, string? lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("userenv.dll", SetLastError = true)]
        private static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

        [DllImport("userenv.dll", SetLastError = true)]
        private static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        private enum SECURITY_IMPERSONATION_LEVEL { SecurityIdentification = 1 }
        private enum TOKEN_TYPE { TokenPrimary = 1 }

        [StructLayout(LayoutKind.Sequential)]
        private struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public bool bInheritHandle;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct STARTUPINFO
        {
            public int cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public int dwX, dwY, dwXSize, dwYSize;
            public int dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
            public short wShowWindow, cbReserved2;
            public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        #endregion
    }
}
