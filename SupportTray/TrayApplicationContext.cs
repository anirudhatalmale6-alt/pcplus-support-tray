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

        public TrayApplicationContext()
        {
            _config = AppConfig.Load();

            _trayIcon = new NotifyIcon
            {
                Icon = CreateDefaultIcon(),
                Text = $"{_config.CompanyName} Support",
                Visible = true,
                ContextMenuStrip = CreateContextMenu()
            };

            _trayIcon.DoubleClick += (s, e) => ShowChatForm();

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

            // Create a programmatic icon: blue circle with "PC" text
            using var bitmap = new Bitmap(32, 32);
            using var g = Graphics.FromImage(bitmap);
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.AntiAliasGridFit;

            // Blue circle background
            using var bgBrush = new SolidBrush(Color.FromArgb(0, 120, 212));
            g.FillEllipse(bgBrush, 1, 1, 30, 30);

            // White border
            using var borderPen = new Pen(Color.White, 1.5f);
            g.DrawEllipse(borderPen, 1, 1, 30, 30);

            // "PC" text
            using var font = new Font("Segoe UI", 11, FontStyle.Bold);
            using var textBrush = new SolidBrush(Color.White);
            var textSize = g.MeasureString("PC", font);
            g.DrawString("PC", font, textBrush,
                (32 - textSize.Width) / 2,
                (32 - textSize.Height) / 2);

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

            // Chat with Support (primary action)
            var chatItem = new ToolStripMenuItem("Chat with Support");
            chatItem.Font = new Font("Segoe UI", 9.5f, FontStyle.Bold);
            chatItem.Click += (s, e) => ShowChatForm();
            menu.Items.Add(chatItem);

            // WhatsApp
            var whatsappItem = new ToolStripMenuItem("WhatsApp Support");
            whatsappItem.Click += (s, e) => OpenWhatsApp();
            menu.Items.Add(whatsappItem);

            // Text/SMS
            var smsItem = new ToolStripMenuItem("Text/SMS Support");
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
            var phone = _config.SupportPhone;
            if (string.IsNullOrEmpty(phone))
                phone = "6047601662";

            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = $"sms:{phone}",
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
                $"Support Utility v3.0\n\n" +
                $"Quick access to:\n" +
                $"  - Live chat with support team\n" +
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
