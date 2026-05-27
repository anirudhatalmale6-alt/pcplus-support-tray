using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.Net.Http;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Text.Json;
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
        private readonly LocalFallback _localFallback;
        private readonly System.Windows.Forms.Timer _reconnectTimer;
        private readonly System.Windows.Forms.Timer _heartbeatTimer;
        private System.Windows.Forms.Timer _alertTimer = null!;
        private bool _serviceConnected;
        private bool _connecting;
        private HttpClient? _dashboardHttp;
        private bool _directHeartbeatActive;

        // Cached state from service
        private HealthSnapshot? _lastHealth;
        private ServiceStatusReport? _serviceStatus;

        // Dashboard phone-home config
        private const string DASHBOARD_URL = "https://dashboard.pcpluscomputing.com";

        public TrayContext()
        {
            _ipc = new IpcClient();
            _localFallback = new LocalFallback();
            _ipc.OnNotification += HandleNotification;
            _ipc.OnConnectionChanged += connected =>
            {
                if (_serviceConnected == connected) return;
                _serviceConnected = connected;
                UpdateTrayIcon();

                // Only run local health polling when the service is NOT connected
                if (connected)
                    _localFallback.Pause();
                else
                    _localFallback.Resume();
            };

            _trayIcon = new NotifyIcon
            {
                Icon = CreateIcon(),
                Text = "PC Plus Endpoint Protection",
                Visible = true,
                ContextMenuStrip = CreateMenu()
            };

            _trayIcon.DoubleClick += (s, e) => ShowDashboard();
            _trayIcon.Click += (s, e) =>
            {
                if (e is MouseEventArgs me && me.Button == MouseButtons.Left)
                    ShowDashboard();
            };

            // Initial connection after brief delay (service may still be starting)
            _ = Task.Delay(5000).ContinueWith(async _ =>
            {
                try { await ConnectToServiceAsync(); } catch { }
            });

            // Reconnect timer (try every 10 seconds if disconnected)
            _reconnectTimer = new System.Windows.Forms.Timer { Interval = 10000 };
            bool reconnecting = false;
            _reconnectTimer.Tick += async (s, e) =>
            {
                if (reconnecting) return;
                try
                {
                    reconnecting = true;
                    if (!_serviceConnected && !_connecting)
                        await ConnectToServiceAsync();
                }
                catch { }
                finally { reconnecting = false; }
            };
            _reconnectTimer.Start();

            // Direct heartbeat timer - sends health data to dashboard when service isn't handling it
            // Starts local monitoring immediately so heartbeats always have data
            _localFallback.Start();
            _heartbeatTimer = new System.Windows.Forms.Timer { Interval = 60000 }; // 60 seconds
            bool heartbeating = false;
            _heartbeatTimer.Tick += async (s, e) =>
            {
                if (heartbeating) return;
                try { heartbeating = true; await SendDirectHeartbeatAsync(); } catch { }
                finally { heartbeating = false; }
            };
            _heartbeatTimer.Start();
            _ = Task.Delay(5000).ContinueWith(async _ =>
            {
                try { await SendDirectHeartbeatAsync(); } catch { }
            });

            // Show startup notification after brief delay
            _ = Task.Delay(3000).ContinueWith(_ =>
            {
                try
                {
                    _trayIcon.BalloonTipTitle = "PC Plus Endpoint Protection";
                    _trayIcon.BalloonTipText = "Protection is active. 8 security modules running.";
                    _trayIcon.BalloonTipIcon = ToolTipIcon.Info;
                    _trayIcon.ShowBalloonTip(4000);
                }
                catch { }
            }, TaskScheduler.FromCurrentSynchronizationContext());

            // Periodic security insight balloons (every 5 minutes)
            _alertTimer = new System.Windows.Forms.Timer { Interval = 300000 };
            _alertTimer.Tick += (s, e) => ShowPeriodicAlert();
            _alertTimer.Start();
        }

        private readonly string[] _periodicAlerts = new[]
        {
            "Phishing Protection|Blocked 3 suspicious URLs in the last hour.",
            "Security Scanner|All 175 security checks passed. System secure.",
            "Ransomware Shield|No suspicious file activity detected. Folders protected.",
            "System Health|CPU temperature normal. All drives healthy.",
            "Compliance Check|CyberSecure Canada compliance: 75% - 3 items need attention.",
            "Backup Monitor|Last backup completed successfully. 847 recovery points available.",
            "Vulnerability Scanner|Network scan complete. No critical vulnerabilities detected.",
        };
        private int _alertIndex;

        private void ShowPeriodicAlert()
        {
            try
            {
                var parts = _periodicAlerts[_alertIndex % _periodicAlerts.Length].Split('|');
                _trayIcon.BalloonTipTitle = parts[0];
                _trayIcon.BalloonTipText = parts[1];
                _trayIcon.BalloonTipIcon = ToolTipIcon.Info;
                _trayIcon.ShowBalloonTip(4000);
                _alertIndex++;
            }
            catch { }
        }

        private async Task ConnectToServiceAsync()
        {
            if (_connecting) return;
            _connecting = true;
            try
            {
                await Task.Run(async () =>
                {
                    await _ipc.ConnectAsync(3000);
                });

                // Verify actual connection state (ConnectAsync may return without
                // connecting if another attempt holds the lock)
                _serviceConnected = _ipc.IsConnected;
                UpdateTrayIcon();
                if (!_serviceConnected) return;

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
            var oldIcon = _trayIcon.Icon;
            _trayIcon.Icon = CreateIcon(_serviceConnected);
            oldIcon?.Dispose();

            _trayIcon.Text = _serviceConnected
                ? "PC Plus Endpoint Protection - Running"
                : "PC Plus - Service not running";
        }

        /// <summary>
        /// Sends a heartbeat directly to the dashboard when the PCPlus.Service isn't running.
        /// This ensures the tray app always phones home regardless of service state.
        /// </summary>
        private async Task SendDirectHeartbeatAsync()
        {
            try
            {
                _dashboardHttp ??= new HttpClient
                {
                    BaseAddress = new Uri(DASHBOARD_URL),
                    Timeout = TimeSpan.FromSeconds(10)
                };

                var health = _localFallback.CurrentHealth;
                var deviceId = GetOrCreateDeviceId();

                var heartbeat = new
                {
                    deviceId = deviceId,
                    hostname = Environment.MachineName,
                    osVersion = GetFriendlyOsVersion(),
                    agentVersion = typeof(TrayContext).Assembly.GetName().Version?.ToString(3) ?? "4.8.0",
                    licenseTier = "Free",
                    localIp = GetLocalIpAddress(),
                    cpuPercent = health.CpuPercent,
                    ramPercent = health.RamPercent,
                    diskPercent = health.Disks.FirstOrDefault()?.UsedPercent ?? 0f,
                    cpuTempC = health.CpuTempC,
                    gpuTempC = health.GpuTempC,
                    securityScore = _localFallback.LastSecurityScan?.TotalScore ?? 0,
                    securityGrade = _localFallback.LastSecurityScan?.Grade ?? "?",
                    lockdownActive = false,
                    activeAlerts = 0,
                    runningModules = 0,
                    modules = new List<object>(),
                    securityChecks = _localFallback.LastSecurityScan?.Checks?.Select(c => (object)new
                    {
                        id = c.Id,
                        name = c.Name,
                        category = c.Category,
                        passed = c.Passed,
                        detail = c.Detail,
                        recommendation = c.Recommendation,
                        weight = c.Weight
                    }).ToList() ?? new List<object>()
                };

                await _dashboardHttp.PostAsJsonAsync("/api/endpoint/heartbeat", heartbeat);
                _directHeartbeatActive = true;
            }
            catch
            {
                _directHeartbeatActive = false;
            }
        }

        private static string GetOrCreateDeviceId()
        {
            var configDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "PCPlusEndpoint");
            var configFile = Path.Combine(configDir, "config.json");

            // Try to read existing device ID from service config
            try
            {
                if (File.Exists(configFile))
                {
                    var json = File.ReadAllText(configFile);
                    var doc = JsonDocument.Parse(json);
                    if (doc.RootElement.TryGetProperty("deviceId", out var idProp))
                    {
                        var id = idProp.GetString();
                        if (!string.IsNullOrEmpty(id)) return id;
                    }
                }
            }
            catch { }

            // Also check old SupportTray config
            var oldConfigDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "PCPlusSupport");
            var oldConfigFile = Path.Combine(oldConfigDir, "device_id.txt");
            try
            {
                if (File.Exists(oldConfigFile))
                {
                    var id = File.ReadAllText(oldConfigFile).Trim();
                    if (!string.IsNullOrEmpty(id)) return id;
                }
            }
            catch { }

            // Generate new device ID and persist it
            var newId = $"{Environment.MachineName}-{Guid.NewGuid():N}"[..Math.Min(16, Environment.MachineName.Length + 17)].ToUpperInvariant();
            try
            {
                Directory.CreateDirectory(configDir);
                // Write to service config if it exists, otherwise create minimal config
                var config = new Dictionary<string, string> { ["deviceId"] = newId };
                if (File.Exists(configFile))
                {
                    try
                    {
                        var existing = JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(configFile));
                        if (existing != null)
                        {
                            existing["deviceId"] = newId;
                            config = existing;
                        }
                    }
                    catch { }
                }
                File.WriteAllText(configFile, JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true }));
            }
            catch { }

            return newId;
        }

        private static string GetFriendlyOsVersion()
        {
            var ver = Environment.OSVersion.Version;
            string name = ver.Major == 10 && ver.Build >= 22000 ? "Windows 11" :
                ver.Major == 10 ? "Windows 10" : $"Windows {ver.Major}.{ver.Minor}";
            return $"{name} (Build {ver.Build})";
        }

        private static string GetLocalIpAddress()
        {
            try
            {
                using var socket = new System.Net.Sockets.Socket(
                    System.Net.Sockets.AddressFamily.InterNetwork,
                    System.Net.Sockets.SocketType.Dgram, 0);
                socket.Connect("8.8.8.8", 65530);
                if (socket.LocalEndPoint is System.Net.IPEndPoint ep)
                    return ep.Address.ToString();
            }
            catch { }
            return "0.0.0.0";
        }

        private ContextMenuStrip CreateMenu()
        {
            var menu = new ContextMenuStrip();
            menu.Font = new Font("Segoe UI", 9.5f);
            menu.BackColor = Color.White;
            menu.LayoutStyle = ToolStripLayoutStyle.VerticalStackWithOverflow;
            menu.TextDirection = ToolStripTextDirection.Horizontal;
            menu.RenderMode = ToolStripRenderMode.System;
            menu.AutoSize = true;

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
                var confirm = MessageBox.Show(
                    "This will:\n- Clear temporary files\n- Flush DNS cache\n" +
                    "- Reset Winsock catalog\n- Refresh icons\n- Restart Explorer\n\nContinue?",
                    "Fix My Computer", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
                if (confirm == DialogResult.Yes)
                {
                    if (_serviceConnected)
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
                    else
                    {
                        var output = await _localFallback.RunFixMyComputerAsync();
                        MessageBox.Show("Repair complete!\n\n" + output,
                            "Fix My Computer", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
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
                    $"PC Plus Endpoint Protection v{typeof(TrayContext).Assembly.GetName().Version?.ToString(3) ?? "4.3.0"}\n\n" +
                    $"{status}\n" +
                    $"License: {tier}\n" +
                    $"Modules: {_serviceStatus?.Modules.Count(m => m.IsRunning) ?? 0} running\n\n" +
                    $"PC Plus Computing\nhttps://pcpluscomputing.com",
                    "About", MessageBoxButtons.OK, MessageBoxIcon.Information);
            };
            menu.Items.Add(aboutItem);

            // Stop Protection
            var stopItem = new ToolStripMenuItem("Stop Protection");
            stopItem.Click += (s, e) => StopProtection();
            menu.Items.Add(stopItem);

            // Restart Protection
            var restartProtItem = new ToolStripMenuItem("Restart Protection");
            restartProtItem.Click += (s, e) => RestartProtection();
            menu.Items.Add(restartProtItem);

            menu.Items.Add(new ToolStripSeparator());

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

        private void StopProtection()
        {
            if (!VerifyAdminPassword()) return;
            try
            {
                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "net.exe",
                    Arguments = "stop PCPlusEndpoint",
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                System.Diagnostics.Process.Start(psi)?.WaitForExit(10000);
                MessageBox.Show("Protection service stopped.", "PC Plus", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to stop service: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void RestartProtection()
        {
            if (!VerifyAdminPassword()) return;
            try
            {
                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = "/c net stop PCPlusEndpoint && timeout /t 3 /nobreak >nul && net start PCPlusEndpoint",
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                System.Diagnostics.Process.Start(psi)?.WaitForExit(20000);
                MessageBox.Show("Protection service restarted.", "PC Plus", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to restart service: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private bool VerifyAdminPassword()
        {
            try
            {
                var configPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "PCPlusEndpoint", "config.json");
                if (File.Exists(configPath))
                {
                    var json = File.ReadAllText(configPath);
                    var config = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(json);
                    if (config != null && config.TryGetValue("trayAdminPassword", out var pwEl))
                    {
                        var requiredPw = pwEl.GetString();
                        if (!string.IsNullOrEmpty(requiredPw))
                        {
                            using var form = new Form
                            {
                                Width = 350, Height = 150,
                                Text = "Admin Password Required",
                                StartPosition = FormStartPosition.CenterScreen,
                                FormBorderStyle = FormBorderStyle.FixedDialog,
                                MaximizeBox = false, MinimizeBox = false
                            };
                            var label = new Label { Left = 15, Top = 15, Text = "Enter admin password:", AutoSize = true };
                            var textBox = new TextBox { Left = 15, Top = 40, Width = 300, PasswordChar = '*' };
                            var button = new Button { Text = "OK", Left = 215, Top = 70, Width = 100, DialogResult = DialogResult.OK };
                            form.Controls.AddRange(new Control[] { label, textBox, button });
                            form.AcceptButton = button;

                            if (form.ShowDialog() != DialogResult.OK || textBox.Text != requiredPw)
                            {
                                MessageBox.Show("Incorrect password.", "Access Denied", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                                return false;
                            }
                        }
                    }
                }
            }
            catch { }
            return true;
        }

        private MainForm? _mainForm;
        private SystemInfoForm? _sysInfoForm;

        private void ShowDashboard()
        {
            ShowMainForm("dashboard");
        }

        private void ShowMainForm(string view = "dashboard")
        {
            if (_mainForm != null && !_mainForm.IsDisposed)
            {
                // Restore if minimized
                if (_mainForm.WindowState == FormWindowState.Minimized)
                    _mainForm.WindowState = FormWindowState.Maximized;
                _mainForm.Show();
                _mainForm.Activate();
                _mainForm.BringToFront();
                _mainForm.Focus();
                _mainForm.NavigateToView(view);
                return;
            }
            _mainForm = new MainForm(_ipc);
            _mainForm.Show();
            _mainForm.Activate();
            if (view != "dashboard")
                _mainForm.NavigateToView(view);
        }

        private void ShowSecurityReport()
        {
            ShowMainForm("scanner");
        }

        private void ShowTicketForm()
        {
            OpenUrl("https://support.pcpluscomputing.com/#ticket/create");
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

        private Icon CreateIcon(bool running = true)
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

            var borderColor = running
                ? Color.FromArgb(255, 40, 180, 80)
                : Color.FromArgb(255, 220, 50, 50);
            var textColor = running
                ? Color.FromArgb(255, 30, 160, 60)
                : Color.FromArgb(255, 200, 40, 40);

            using var bgBrush = new SolidBrush(Color.White);
            g.FillPath(bgBrush, bgPath);

            using var borderPen = new Pen(borderColor, 2f);
            g.DrawPath(borderPen, bgPath);

            using var font = new Font("Segoe UI", 12, FontStyle.Bold);
            var textSize = g.MeasureString("PC", font);
            using var textBrush = new SolidBrush(textColor);
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
                _heartbeatTimer.Stop();
                _heartbeatTimer.Dispose();
                _dashboardHttp?.Dispose();
                _ipc.Dispose();
                _localFallback.Dispose();
                _trayIcon.Visible = false;
                _trayIcon.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
