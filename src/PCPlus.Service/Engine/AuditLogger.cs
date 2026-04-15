namespace PCPlus.Service.Engine
{
    /// <summary>
    /// Audit logger - logs all actions to dated log files.
    /// Required by Paul's spec: "Log all actions for auditing."
    /// </summary>
    public class AuditLogger
    {
        private readonly string _logDir;
        private readonly object _lock = new();

        public AuditLogger(string logDir)
        {
            _logDir = logDir;
            Directory.CreateDirectory(_logDir);
        }

        public void Log(string module, string action, string detail)
        {
            var line = $"[{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss.fff}] [{module}] [{action}] {detail}";
            var logFile = Path.Combine(_logDir, $"audit_{DateTime.UtcNow:yyyyMMdd}.log");

            lock (_lock)
            {
                try
                {
                    File.AppendAllText(logFile, line + Environment.NewLine);
                }
                catch { }
            }

            // Cleanup old logs (keep 30 days)
            CleanupOldLogs();
        }

        private void CleanupOldLogs()
        {
            try
            {
                var cutoff = DateTime.UtcNow.AddDays(-30);
                foreach (var file in Directory.GetFiles(_logDir, "audit_*.log"))
                {
                    if (File.GetCreationTimeUtc(file) < cutoff)
                    {
                        try { File.Delete(file); } catch { }
                    }
                }
            }
            catch { }
        }
    }
}
