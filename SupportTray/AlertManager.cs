using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Windows.Forms;

namespace SupportTray
{
    /// <summary>
    /// Manages health alerts - shows balloon notifications, logs alerts to file,
    /// and maintains alert history for the dashboard.
    /// </summary>
    public class AlertManager : IDisposable
    {
        private readonly NotifyIcon _trayIcon;
        private readonly List<AlertRecord> _history = new();
        private readonly object _lock = new();
        private readonly string _logFile;
        private bool _disposed;

        // Settings
        public bool ShowBalloons { get; set; } = true;
        public bool LogToFile { get; set; } = true;
        public int MaxHistorySize { get; set; } = 200;

        // Dynamic tray icon color based on health
        public bool DynamicTrayIcon { get; set; } = true;
        private HealthStatus _currentStatus = HealthStatus.Healthy;

        public event Action<AlertRecord>? OnNewAlert;

        public AlertManager(NotifyIcon trayIcon)
        {
            _trayIcon = trayIcon;

            var logDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "PCPlusSupport", "Logs");
            Directory.CreateDirectory(logDir);
            _logFile = Path.Combine(logDir, "health_alerts.log");
        }

        public void HandleHealthAlert(HealthAlert alert)
        {
            var record = new AlertRecord
            {
                Key = alert.Key,
                Message = alert.Message,
                Severity = alert.Severity,
                Timestamp = alert.Timestamp
            };

            lock (_lock)
            {
                _history.Add(record);
                while (_history.Count > MaxHistorySize)
                    _history.RemoveAt(0);
            }

            // Balloon notification
            if (ShowBalloons)
            {
                var icon = alert.Severity switch
                {
                    AlertSeverity.Critical => ToolTipIcon.Error,
                    AlertSeverity.Warning => ToolTipIcon.Warning,
                    _ => ToolTipIcon.Info
                };

                _trayIcon.BalloonTipTitle = alert.Severity == AlertSeverity.Critical
                    ? "Health Alert - Critical"
                    : "Health Alert";
                _trayIcon.BalloonTipText = alert.Message;
                _trayIcon.BalloonTipIcon = icon;
                _trayIcon.ShowBalloonTip(5000);
            }

            // Log to file
            if (LogToFile)
            {
                try
                {
                    var line = $"[{alert.Timestamp:yyyy-MM-dd HH:mm:ss}] [{alert.Severity}] {alert.Message}";
                    File.AppendAllText(_logFile, line + Environment.NewLine);
                }
                catch { }
            }

            // Update tray icon status
            UpdateStatus(alert.Severity);

            OnNewAlert?.Invoke(record);
        }

        public void HandleHealthUpdate(HealthSnapshot snapshot)
        {
            // Determine overall status from snapshot
            var status = HealthStatus.Healthy;

            if (snapshot.CpuPercent > 90 || snapshot.RamPercent > 95 ||
                snapshot.CpuTempC > 90 || snapshot.GpuTempC > 95)
            {
                status = HealthStatus.Critical;
            }
            else if (snapshot.CpuPercent > 75 || snapshot.RamPercent > 85 ||
                     snapshot.CpuTempC > 75 || snapshot.GpuTempC > 80 ||
                     snapshot.Disks.Any(d => d.UsedPercent > 90))
            {
                status = HealthStatus.Warning;
            }

            if (status != _currentStatus)
            {
                _currentStatus = status;
                UpdateTrayTooltip(snapshot);
            }
        }

        private void UpdateStatus(AlertSeverity severity)
        {
            if (severity == AlertSeverity.Critical)
                _currentStatus = HealthStatus.Critical;
            else if (severity == AlertSeverity.Warning && _currentStatus != HealthStatus.Critical)
                _currentStatus = HealthStatus.Warning;
        }

        private void UpdateTrayTooltip(HealthSnapshot snap)
        {
            try
            {
                var tooltip = $"CPU: {snap.CpuPercent:F0}%  RAM: {snap.RamPercent:F0}%";
                if (snap.CpuTempC > 0)
                    tooltip += $"  Temp: {snap.CpuTempC:F0}C";

                // NotifyIcon.Text max is 63 chars
                if (tooltip.Length > 63)
                    tooltip = tooltip.Substring(0, 63);

                _trayIcon.Text = tooltip;
            }
            catch { }
        }

        public List<AlertRecord> GetHistory()
        {
            lock (_lock)
            {
                return new List<AlertRecord>(_history);
            }
        }

        public List<AlertRecord> GetRecentAlerts(int count = 10)
        {
            lock (_lock)
            {
                return _history.TakeLast(count).Reverse().ToList();
            }
        }

        public void ClearHistory()
        {
            lock (_lock)
            {
                _history.Clear();
            }
            _currentStatus = HealthStatus.Healthy;
        }

        public HealthStatus CurrentStatus => _currentStatus;

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
        }
    }

    public class AlertRecord
    {
        public string Key { get; set; } = "";
        public string Message { get; set; } = "";
        public AlertSeverity Severity { get; set; }
        public DateTime Timestamp { get; set; }
    }

    public enum HealthStatus
    {
        Healthy,
        Warning,
        Critical
    }
}
