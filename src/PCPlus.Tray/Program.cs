using System;
using System.Windows.Forms;

namespace PCPlus.Tray
{
    static class Program
    {
        private static readonly string CrashLogPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "PCPlusEndpoint", "Logs", "tray-crashes.log");

        [STAThread]
        static void Main(string[] args)
        {
            Application.SetHighDpiMode(HighDpiMode.PerMonitorV2);
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            Application.ThreadException += (s, e) => LogCrash("UI Thread", e.Exception);
            AppDomain.CurrentDomain.UnhandledException += (s, e) =>
                LogCrash("AppDomain", e.ExceptionObject as Exception);
            TaskScheduler.UnobservedTaskException += (s, e) =>
            {
                LogCrash("UnobservedTask", e.Exception);
                e.SetObserved();
            };

            bool createdNew;
            using var mutex = new System.Threading.Mutex(true, "PCPlusEndpoint_Tray", out createdNew);
            if (!createdNew)
                return;

            try
            {
                Application.Run(new TrayContext());
            }
            catch (Exception ex)
            {
                LogCrash("Main", ex);
            }
        }

        private static void LogCrash(string source, Exception? ex)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(CrashLogPath)!);
                var entry = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] [{source}] {ex?.GetType().Name}: {ex?.Message}\n{ex?.StackTrace}\n\n";
                File.AppendAllText(CrashLogPath, entry);
            }
            catch { }
        }
    }
}
