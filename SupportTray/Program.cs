using System;
using System.IO;
using System.Windows.Forms;

namespace SupportTray
{
    static class Program
    {
        private static readonly string LogDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "PCPlusSupport", "Logs");

        [STAThread]
        static void Main(string[] args)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
            Application.ThreadException += (s, e) => LogCrash(e.Exception);
            AppDomain.CurrentDomain.UnhandledException += (s, e) =>
                LogCrash(e.ExceptionObject as Exception);

            // Prevent multiple instances
            bool createdNew;
            using var mutex = new System.Threading.Mutex(true, "PCPlusSupportTray_SingleInstance", out createdNew);
            if (!createdNew)
            {
                MessageBox.Show("PC Plus Support is already running.", "PC Plus Support",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            Application.Run(new TrayApplicationContext());
        }

        internal static void LogCrash(Exception? ex)
        {
            try
            {
                Directory.CreateDirectory(LogDir);
                var logFile = Path.Combine(LogDir, "crash.log");
                var entry = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {ex?.GetType().Name}: {ex?.Message}\n{ex?.StackTrace}\n\n";
                File.AppendAllText(logFile, entry);
            }
            catch { }
        }

        internal static void LogError(string context, Exception? ex)
        {
            try
            {
                Directory.CreateDirectory(LogDir);
                var logFile = Path.Combine(LogDir, "errors.log");
                var entry = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] [{context}] {ex?.GetType().Name}: {ex?.Message}\n";
                File.AppendAllText(logFile, entry);

                // Keep log under 1MB
                var info = new FileInfo(logFile);
                if (info.Exists && info.Length > 1_048_576)
                {
                    var lines = File.ReadAllLines(logFile);
                    File.WriteAllLines(logFile, lines.AsSpan(lines.Length / 2).ToArray());
                }
            }
            catch { }
        }
    }
}
