using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.Windows.Forms;
using PCPlus.Core.IPC;
using PCPlus.Core.Models;
using PCPlus.Tray.Forms;

namespace PCPlus.Tray
{
    /// <summary>
    /// Tray application context. UI only - all logic runs in the Windows Service.
    /// Communicates with PCPlusService via named pipes (IPC).
    /// </summary>
    public class TrayContext : ApplicationContext
    {
        private readonly NotifyIcon _trayIcon;
        private readonly IpcClient _ipc;
        private readonly System.Windows.Forms.Timer _reconnectTimer;
        private bool _serviceConnected;
        private bool _connecting;

        // Cached state from service
        private HealthSnapshot? _lastHealth;
        private ServiceStatusReport? _serviceStatus;

        public TrayContext()
        {
            _ipc = new IpcClient();
            _ipc.OnNotification += HandleNotification;
            _ipc.OnConnectionChanged += connected =>
            {
                _serviceConnected = connected;
                UpdateTrayIcon();
            };

            _trayIcon = new NotifyIcon
            {
                Icon = CreateIcon(),
                Text = "PC Plus Endpoint Protection",
                Visible = true,
                ContextMenuStrip = CreateMenu()
            };

            _trayIcon.DoubleClick += (s, e) => ShowDashboard();

            // Connect to service
            _ = ConnectToServiceAsync();

            // Reconnect timer (try every 10 seconds if disconnected)
            _reconnectTimer = new System.Windows.Forms.Timer { Interval = 10000 };
            _reconnectTimer.Tick += async (s, e) =>
            {
                if (!_serviceConnected && !_connecting)
                    await ConnectToServiceAsync();
            };
            _reconnectTimer.Start();
        }

        private async Task ConnectToServiceAsync()
        {
            if (_connecting) return;
            _connecting = true;
            try
            {
                // Run IPC connection off the UI thread to prevent freezing
                await Task.Run(async () =>
                {
                    await _ipc.ConnectAsync(3000);
                });
                _serviceConnected = true;
                UpdateTrayIcon();

                // Get initial status (also off UI thread)
                var response = await Task.Run(async () => await _ipc.GetServiceStatusAsync());
                if (response.Success)
                {
                    _serviceStatus = response.GetData<ServiceStatusReport>();
                }
            }
            catch
            {
                _serviceConnected = false;
                UpdateTrayIcon();
            }
            finally
            {
                _connecting = false;
            }
        }

        private void HandleNotification(IpcNotification notification)
        {
            try
            {
                switch (notification.Type)
                {
                    case IpcNotification.HEALTH_UPDATE:
                        _lastHealth = notification.GetData<HealthSnapshot>();
                        UpdateTooltip();
                        break;

                    case IpcNotification.ALERT:
                        var alert = notification.GetData<Alert>();
                        if (alert != null)
                            ShowAlertBalloon(alert);
                        break;

                    case IpcNotification.THREAT_DETECTED:
                        ShowThreatBalloon();
                        break;

                    case IpcNotification.LOCKDOWN_CHANGED:
                        UpdateTrayIcon();
                        break;
                }
            }
            catch { }
        }

        private void UpdateTooltip()
        {
            if (_lastHealth == null) return;
            try
            {
                var tip = $"CPU: {_lastHealth.CpuPercent:F0}%  RAM: {_lastHealth.RamPercent:F0}%";
                if (_lastHealth.CpuTempC > 0)
                    tip += $"  Temp: {_lastHealth.CpuTempC:F0}C";
                if (tip.Length > 63) tip = tip[..63];
                _trayIcon.Text = tip;
            }
            catch { }
        }

        private void ShowAlertBalloon(Alert alert)
        {
            try
            {
                _trayIcon.BalloonTipTitle = alert.Title;
                _trayIcon.BalloonTipText = alert.Message;
                _trayIcon.BalloonTipIcon = alert.Severity switch
                {
                    AlertSeverity.Emergency => ToolTipIcon.Error,
                    AlertSeverity.Critical => ToolTipIcon.Error,
                    AlertSeverity.Warning => ToolTipIcon.Warning,
                    _ => ToolTipIcon.Info
                };
                _trayIcon.ShowBalloonTip(5000);
            }
            catch { }
        }

        private void ShowThreatBalloon()
        {
            _trayIcon.BalloonTipTitle = "THREAT DETECTED";
            _trayIcon.BalloonTipText = "A potential ransomware threat was detected. Click for details.";
            _trayIcon.BalloonTipIcon = ToolTipIcon.Error;
            _trayIcon.ShowBalloonTip(10000);
        }

        private void UpdateTrayIcon()
        {
            // Icon could change color based on status
            // For now, just update tooltip
            if (!_serviceConnected)
                _trayIcon.Text = "PC Plus - Service not running";
        }

        private ContextMenuStrip CreateMenu()
        {
            var menu = new ContextMenuStrip();
            menu.Font = new Font("Segoe UI", 9.5f);
            menu.BackColor = Color.White;

            // Header
            var header = new ToolStripMenuItem($"  PC Plus Endpoint Protection")
            { Enabled = false, Font = new Font("Segoe UI", 10, FontStyle.Bold) };
            menu.Items.Add(header);
            menu.Items.Add(new ToolStripSeparator());

            // Health Dashboard (primary)
            var dashItem = new ToolStripMenuItem("Health Dashboard")
            { Font = new Font("Segoe UI", 9.5f, FontStyle.Bold) };
            dashItem.Click += (s, e) => ShowDashboard();
            menu.Items.Add(dashItem);

            // Security Report
            var secItem = new ToolStripMenuItem("Security Report");
            secItem.Click += (s, e) => ShowSecurityReport();
            menu.Items.Add(secItem);

            menu.Items.Add(new ToolStripSeparator());

            // Live Chat
            var chatItem = new ToolStripMenuItem("Live Chat");
            chatItem.Click += (s, e) => OpenUrl("https://support.pcpluscomputing.com/livechat.html");
            menu.Items.Add(chatItem);

            // Support Ticket
            var ticketItem = new ToolStripMenuItem("Create Support Ticket");
            ticketItem.Click += (s, e) => ShowTicketForm();
            menu.Items.Add(ticketItem);

            // Remote Support
            var remoteItem = new ToolStripMenuItem("Remote Support");
            remoteItem.Click += (s, e) => OpenQuickAssist();
            menu.Items.Add(remoteItem);

            menu.Items.Add(new ToolStripSeparator());

            // Fix My Computer (one-click)
            var fixItem = new ToolStripMenuItem("Fix My Computer");
            fixItem.Click += async (s, e) =>
            {
                var result = MessageBox.Show(
                    "This will:\n- Clear temporary files\n- Flush DNS cache\n" +
                    "- Reset network stack\n- Run System File Checker\n- Refresh Explorer\n\nContinue?",
                    "Fix My Computer", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
                if (result == DialogResult.Yes)
                {
                    var response = await _ipc.SendModuleCommandAsync("maintenance", "RunMaintenance",
                        new() { ["action"] = "fixmypc" });
                    if (response.Success)
                        MessageBox.Show("Repair complete! Your computer has been optimized.",
                            "Fix My Computer", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    else
                        MessageBox.Show($"Error: {response.Message}", "Fix My Computer",
                            MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
            };
            menu.Items.Add(fixItem);

            // Screenshots
            var screenshotItem = new ToolStripMenuItem("Take Screenshot");
            screenshotItem.Click += (s, e) => TakeScreenshot();
            menu.Items.Add(screenshotItem);

            // System Info
            var sysItem = new ToolStripMenuItem("System Information");
            sysItem.Click += (s, e) => ShowSystemInfo();
            menu.Items.Add(sysItem);

            menu.Items.Add(new ToolStripSeparator());

            // Website submenu
            var webMenu = new ToolStripMenuItem("Visit Website");
            webMenu.DropDownItems.Add("PC Plus Computing").Click += (s, e) => OpenUrl("https://pcpluscomputing.com");
            webMenu.DropDownItems.Add("Support Forum").Click += (s, e) => OpenUrl("https://forum.pcpluscomputing.com");
            webMenu.DropDownItems.Add("Book Appointment").Click += (s, e) => OpenUrl("https://pcpluscomputing.com/appointments/");
            menu.Items.Add(webMenu);

            // About
            var aboutItem = new ToolStripMenuItem("About");
            aboutItem.Click += (s, e) =>
            {
                var status = _serviceConnected ? "Service: Connected" : "Service: Not Connected";
                var tier = _serviceStatus?.License?.Tier.ToString() ?? "Free";
                MessageBox.Show(
                    $"PC Plus Endpoint Protection v4.0.0\n\n" +
                    $"{status}\n" +
                    $"License: {tier}\n" +
                    $"Modules: {_serviceStatus?.Modules.Count(m => m.IsRunning) ?? 0} running\n\n" +
                    $"PC Plus Computing\nhttps://pcpluscomputing.com",
                    "About", MessageBoxButtons.OK, MessageBoxIcon.Information);
            };
            menu.Items.Add(aboutItem);

            // Exit
            var exitItem = new ToolStripMenuItem("Exit");
            exitItem.Click += (s, e) =>
            {
                var result = MessageBox.Show(
                    "Close the tray app? The background protection service will continue running.",
                    "Exit", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
                if (result == DialogResult.Yes)
                {
                    _trayIcon.Visible = false;
                    Application.Exit();
                }
            };
            menu.Items.Add(exitItem);

            return menu;
        }

        private DashboardForm? _dashboardForm;
        private SecurityReportForm? _securityForm;
        private SystemInfoForm? _sysInfoForm;

        private void ShowDashboard()
        {
            if (_dashboardForm != null && !_dashboardForm.IsDisposed)
            {
                _dashboardForm.BringToFront();
                _dashboardForm.Focus();
                return;
            }
            _dashboardForm = new DashboardForm(_ipc);
            _dashboardForm.Show();
        }

        private void ShowSecurityReport()
        {
            if (_securityForm != null && !_securityForm.IsDisposed)
            {
                _securityForm.BringToFront();
                _securityForm.Focus();
                return;
            }
            _securityForm = new SecurityReportForm(_ipc);
            _securityForm.Show();
        }

        private void ShowTicketForm()
        {
            OpenUrl("https://support.pcpluscomputing.com/ticket");
        }

        private void ShowSystemInfo()
        {
            if (_sysInfoForm != null && !_sysInfoForm.IsDisposed)
            {
                _sysInfoForm.BringToFront();
                _sysInfoForm.Focus();
                return;
            }
            _sysInfoForm = new SystemInfoForm(_ipc);
            _sysInfoForm.Show();
        }

        private void TakeScreenshot()
        {
            try
            {
                var bounds = Screen.PrimaryScreen!.Bounds;
                using var bitmap = new Bitmap(bounds.Width, bounds.Height);
                using var g = Graphics.FromImage(bitmap);
                g.CopyFromScreen(Point.Empty, Point.Empty, bounds.Size);

                var screenshotDir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.MyPictures),
                    "PC Plus Screenshots");
                Directory.CreateDirectory(screenshotDir);

                var filename = $"Screenshot_{DateTime.Now:yyyy-MM-dd_HH-mm-ss}.png";
                var filepath = Path.Combine(screenshotDir, filename);
                bitmap.Save(filepath, ImageFormat.Png);

                _trayIcon.BalloonTipTitle = "Screenshot Saved";
                _trayIcon.BalloonTipText = $"Saved to: {filepath}";
                _trayIcon.BalloonTipIcon = ToolTipIcon.Info;
                _trayIcon.ShowBalloonTip(3000);

                // Open the file
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                { FileName = filepath, UseShellExecute = true });
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Screenshot failed: {ex.Message}", "Screenshot",
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        private void OpenUrl(string url)
        {
            try
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                { FileName = url, UseShellExecute = true });
            }
            catch { }
        }

        private void OpenQuickAssist()
        {
            try
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                { FileName = "ms-quick-assist:", UseShellExecute = true });
            }
            catch
            {
                MessageBox.Show("Quick Assist could not be opened.", "Remote Support",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }

        private Icon CreateIcon()
        {
            using var bitmap = new Bitmap(32, 32);
            using var g = Graphics.FromImage(bitmap);
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.Clear(Color.Transparent);

            using var bgPath = new GraphicsPath();
            bgPath.AddArc(1, 1, 8, 8, 180, 90);
            bgPath.AddArc(23, 1, 8, 8, 270, 90);
            bgPath.AddArc(23, 23, 8, 8, 0, 90);
            bgPath.AddArc(1, 23, 8, 8, 90, 90);
            bgPath.CloseFigure();

            using var bgBrush = new SolidBrush(Color.White);
            g.FillPath(bgBrush, bgPath);

            using var borderPen = new Pen(Color.FromArgb(255, 40, 120, 220), 2f);
            g.DrawPath(borderPen, bgPath);

            using var font = new Font("Segoe UI", 12, FontStyle.Bold);
            var textSize = g.MeasureString("PC", font);
            using var textBrush = new SolidBrush(Color.FromArgb(255, 30, 100, 200));
            g.DrawString("PC", font, textBrush,
                (32 - textSize.Width) / 2, (32 - textSize.Height) / 2 - 1);

            return Icon.FromHandle(bitmap.GetHicon());
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _reconnectTimer.Stop();
                _reconnectTimer.Dispose();
                _ipc.Dispose();
                _trayIcon.Visible = false;
                _trayIcon.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
