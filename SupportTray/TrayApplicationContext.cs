using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Windows.Forms;

namespace SupportTray
{
    public class TrayApplicationContext : ApplicationContext
    {
        private readonly NotifyIcon _trayIcon;
        private readonly AppConfig _config;
        private ChatForm? _chatForm;
        private string _liveChatUrl;

        public TrayApplicationContext()
        {
            _config = AppConfig.Load();

            // Build live chat URL from Zammad URL
            _liveChatUrl = !string.IsNullOrEmpty(_config.ZammadUrl)
                ? _config.ZammadUrl.TrimEnd('/') + "/livechat.html"
                : "";

            _trayIcon = new NotifyIcon
            {
                Icon = CreateDefaultIcon(),
                Text = $"{_config.CompanyName} Support",
                Visible = true,
                ContextMenuStrip = CreateContextMenu()
            };

            _trayIcon.DoubleClick += (s, e) => OpenLiveChat();

            // Show welcome balloon on first run
            var firstRunFile = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "PCPlusSupport", ".firstrun");
            if (!File.Exists(firstRunFile))
            {
                Directory.CreateDirectory(Path.GetDirectoryName(firstRunFile)!);
                File.WriteAllText(firstRunFile, DateTime.Now.ToString());
                _trayIcon.BalloonTipTitle = $"{_config.CompanyName}";
                _trayIcon.BalloonTipText = "Support is just a click away! Right-click this icon for options.";
                _trayIcon.BalloonTipIcon = ToolTipIcon.Info;
                _trayIcon.ShowBalloonTip(5000);
            }

            // Always show desktop overlay on startup
            ShowDesktopOverlay();
        }

        private Icon CreateDefaultIcon()
        {
            // Check for custom icon file
            var exeDir = AppDomain.CurrentDomain.BaseDirectory;
            var customIconPath = Path.Combine(exeDir, "icon.ico");
            if (File.Exists(customIconPath))
            {
                try { return new Icon(customIconPath); }
                catch { }
            }

            // Create modern programmatic icon
            using var bitmap = new Bitmap(32, 32);
            using var g = Graphics.FromImage(bitmap);
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

            // Rounded square background with gradient
            using var bgPath = new GraphicsPath();
            bgPath.AddArc(1, 1, 8, 8, 180, 90);
            bgPath.AddArc(23, 1, 8, 8, 270, 90);
            bgPath.AddArc(23, 23, 8, 8, 0, 90);
            bgPath.AddArc(1, 23, 8, 8, 90, 90);
            bgPath.CloseFigure();

            using var bgBrush = new LinearGradientBrush(
                new Rectangle(0, 0, 32, 32),
                Color.FromArgb(0, 100, 200),
                Color.FromArgb(0, 140, 230),
                LinearGradientMode.ForwardDiagonal);
            g.FillPath(bgBrush, bgPath);

            // Subtle highlight on top
            using var highlightBrush = new LinearGradientBrush(
                new Rectangle(2, 2, 28, 14),
                Color.FromArgb(60, 255, 255, 255),
                Color.FromArgb(0, 255, 255, 255),
                LinearGradientMode.Vertical);
            g.FillPath(highlightBrush, bgPath);

            // "PC" text - crisp white
            using var font = new Font("Segoe UI", 12, FontStyle.Bold);
            using var textBrush = new SolidBrush(Color.White);
            var textSize = g.MeasureString("PC", font);
            g.DrawString("PC", font, textBrush,
                (32 - textSize.Width) / 2,
                (32 - textSize.Height) / 2 - 1);

            var handle = bitmap.GetHicon();
            return Icon.FromHandle(handle);
        }

        private ContextMenuStrip CreateContextMenu()
        {
            var menu = new ContextMenuStrip();
            menu.Font = new Font("Segoe UI", 9.5f);
            menu.ShowImageMargin = true;
            menu.BackColor = Color.White;

            // Header item (disabled, just for branding)
            var headerItem = new ToolStripMenuItem($"  {_config.CompanyName}")
            {
                Enabled = false,
                Font = new Font("Segoe UI", 10, FontStyle.Bold)
            };
            menu.Items.Add(headerItem);
            menu.Items.Add(new ToolStripSeparator());

            // Live Chat (primary action - real-time chat)
            var liveChatItem = new ToolStripMenuItem("Live Chat");
            liveChatItem.Font = new Font("Segoe UI", 9.5f, FontStyle.Bold);
            liveChatItem.Click += (s, e) => OpenLiveChat();
            menu.Items.Add(liveChatItem);

            // Support Tickets (ticket-based conversations)
            var ticketChatItem = new ToolStripMenuItem("Support Tickets");
            ticketChatItem.Click += (s, e) => ShowChatForm();
            menu.Items.Add(ticketChatItem);

            // WhatsApp
            var whatsappItem = new ToolStripMenuItem("WhatsApp Support");
            whatsappItem.Click += (s, e) => OpenWhatsApp();
            menu.Items.Add(whatsappItem);

            // Text/3CX LiveChat
            var smsItem = new ToolStripMenuItem("Text/LiveChat Support");
            smsItem.Click += (s, e) => OpenSMS();
            menu.Items.Add(smsItem);

            // Email
            var emailItem = new ToolStripMenuItem("Email Support");
            emailItem.Click += (s, e) => OpenEmail();
            menu.Items.Add(emailItem);

            menu.Items.Add(new ToolStripSeparator());

            // Create Ticket
            var ticketItem = new ToolStripMenuItem("Create Support Ticket");
            ticketItem.Click += (s, e) => ShowTicketForm();
            menu.Items.Add(ticketItem);

            // Support Portal
            if (!string.IsNullOrEmpty(_config.ZammadUrl))
            {
                var portalItem = new ToolStripMenuItem("Open Support Portal");
                portalItem.Click += (s, e) =>
                {
                    System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = _config.ZammadUrl,
                        UseShellExecute = true
                    });
                };
                menu.Items.Add(portalItem);
            }

            // Screenshot submenu
            var screenshotMenu = new ToolStripMenuItem("Take Screenshot");

            var captureScreen = new ToolStripMenuItem("Capture Screen");
            captureScreen.Click += (s, e) => CaptureAndNotify(false);
            screenshotMenu.DropDownItems.Add(captureScreen);

            var captureAll = new ToolStripMenuItem("Capture All Monitors");
            captureAll.Click += (s, e) => CaptureAndNotify(true);
            screenshotMenu.DropDownItems.Add(captureAll);

            screenshotMenu.DropDownItems.Add(new ToolStripSeparator());

            var openFolder = new ToolStripMenuItem("Open Screenshots Folder");
            openFolder.Click += (s, e) => ScreenCapture.OpenScreenshotFolder();
            screenshotMenu.DropDownItems.Add(openFolder);

            menu.Items.Add(screenshotMenu);

            // System Info
            var sysInfoItem = new ToolStripMenuItem("System Information");
            sysInfoItem.Click += (s, e) => ShowSystemInfo();
            menu.Items.Add(sysInfoItem);

            menu.Items.Add(new ToolStripSeparator());

            // About
            var aboutItem = new ToolStripMenuItem("About");
            aboutItem.Click += (s, e) => ShowAbout();
            menu.Items.Add(aboutItem);

            // Exit
            var exitItem = new ToolStripMenuItem("Exit");
            exitItem.Click += (s, e) =>
            {
                var result = MessageBox.Show(
                    "Are you sure you want to close the support utility?\n\nYou won't be able to chat or create tickets until it's restarted.",
                    "Close Support Utility",
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Question);
                if (result == DialogResult.Yes)
                {
                    _trayIcon.Visible = false;
                    Application.Exit();
                }
            };
            menu.Items.Add(exitItem);

            return menu;
        }

        private void ShowDesktopOverlay()
        {
            var overlay = new DesktopOverlay();
            overlay.Show();
        }

        private void OpenLiveChat()
        {
            if (!string.IsNullOrEmpty(_liveChatUrl))
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName = _liveChatUrl,
                    UseShellExecute = true
                });
            }
            else
            {
                // Fallback to ticket-based chat if Zammad not configured
                ShowChatForm();
            }
        }

        private void ShowChatForm()
        {
            if (_chatForm == null || _chatForm.IsDisposed)
            {
                _chatForm = new ChatForm(_config);
                _chatForm.Show();
            }
            else
            {
                _chatForm.WindowState = FormWindowState.Normal;
                _chatForm.BringToFront();
                _chatForm.Activate();
            }
        }

        private void ShowTicketForm()
        {
            var form = new TicketForm(_config);
            form.ShowDialog();
        }

        private void ShowSystemInfo()
        {
            var form = new SystemInfoForm(_config);
            form.ShowDialog();
        }

        private void CaptureAndNotify(bool allScreens)
        {
            try
            {
                var path = allScreens ? ScreenCapture.CaptureAllScreens() : ScreenCapture.CaptureFullScreen();
                _trayIcon.BalloonTipTitle = "Screenshot Captured";
                _trayIcon.BalloonTipText = $"Saved to: {Path.GetFileName(path)}\nClick to open folder.";
                _trayIcon.BalloonTipIcon = ToolTipIcon.Info;

                EventHandler? handler = null;
                handler = (s, e) =>
                {
                    _trayIcon.BalloonTipClicked -= handler;
                    ScreenCapture.OpenScreenshotFolder();
                };
                _trayIcon.BalloonTipClicked += handler;
                _trayIcon.ShowBalloonTip(3000);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to capture screenshot: {ex.Message}", "Error",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void OpenWhatsApp()
        {
            var phone = _config.SupportPhone;
            if (string.IsNullOrEmpty(phone))
                phone = "16047601662";

            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = $"https://wa.me/{phone}",
                UseShellExecute = true
            });
        }

        private void OpenSMS()
        {
            var url = _config.LiveChatUrl;
            if (string.IsNullOrEmpty(url))
            {
                var phone = _config.SupportPhone;
                if (string.IsNullOrEmpty(phone)) phone = "6047601662";
                url = $"sms:{phone}";
            }
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = url,
                UseShellExecute = true
            });
        }

        private void OpenEmail()
        {
            var email = _config.SupportEmail;
            if (string.IsNullOrEmpty(email))
            {
                MessageBox.Show("Email support is not configured yet.\nPlease use Chat or WhatsApp.",
                    "Email Not Configured", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            var hostname = SystemInfo.GetHostname();
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = $"mailto:{email}?subject=Support Request from {hostname}",
                UseShellExecute = true
            });
        }

        private void ShowAbout()
        {
            MessageBox.Show(
                $"{_config.CompanyName}\n" +
                $"Support Utility v3.1.1\n\n" +
                $"Quick access to:\n" +
                $"  - Live chat with support team\n" +
                $"  - Support ticket conversations\n" +
                $"  - WhatsApp & SMS support\n" +
                $"  - Create support tickets\n" +
                $"  - Capture & upload screenshots\n" +
                $"  - View system information\n\n" +
                $"RMM Server: {_config.RmmUrl}\n" +
                $"Agent ID: {SystemInfo.GetTacticalAgentId() ?? "Not detected"}",
                $"About {_config.CompanyName} Support",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _trayIcon.Visible = false;
                _trayIcon.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
