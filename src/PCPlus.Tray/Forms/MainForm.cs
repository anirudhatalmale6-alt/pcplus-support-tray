using System.Drawing;
using System.Drawing.Drawing2D;
using System.Management;
using System.Windows.Forms;
using PCPlus.Core.IPC;
using PCPlus.Core.Models;

namespace PCPlus.Tray.Forms
{
    /// <summary>
    /// Main application window - Malwarebytes-style unified UI.
    /// Left sidebar navigation with Dashboard, Scanner, Real-Time Protection,
    /// Detection History, and Settings views.
    /// </summary>
    public class MainForm : Form
    {
        private readonly IpcClient _ipc;
        private readonly LocalFallback _localFallback;
        private readonly System.Windows.Forms.Timer _refreshTimer;
        private bool _usingLocalFallback;

        // Theme colors - clean, professional light theme like Malwarebytes
        private static readonly Color SidebarBg = Color.FromArgb(22, 27, 34);
        private static readonly Color SidebarText = Color.FromArgb(180, 190, 210);
        private static readonly Color SidebarActive = Color.FromArgb(36, 41, 51);
        private static readonly Color SidebarHover = Color.FromArgb(30, 35, 44);
        private static readonly Color ContentBg = Color.FromArgb(246, 248, 250);
        private static readonly Color CardBg = Color.White;
        private static readonly Color CardBorder = Color.FromArgb(220, 225, 230);
        private static readonly Color TextDark = Color.FromArgb(30, 30, 30);
        private static readonly Color TextMuted = Color.FromArgb(100, 110, 120);
        private static readonly Color AccentTeal = Color.FromArgb(0, 120, 215);  // Blue to match PC Plus branding
        private static readonly Color AccentGreen = Color.FromArgb(46, 184, 92);
        private static readonly Color AccentOrange = Color.FromArgb(245, 166, 35);
        private static readonly Color AccentRed = Color.FromArgb(220, 53, 69);
        private static readonly Color AccentBlue = Color.FromArgb(56, 132, 244);

        // Cached data
        private HealthSnapshot? _health;
        private SecurityScanResult? _securityResult;
        private ServiceStatusReport? _serviceStatus;
        private List<Alert> _alerts = new();

        // UI
        private Panel _sidebar = null!;
        private Panel _contentArea = null!;
        private Panel _headerBar = null!;
        private string _currentView = "dashboard";
        private readonly Dictionary<string, Panel> _navButtons = new();

        public MainForm(IpcClient ipc)
        {
            _ipc = ipc;
            _localFallback = new LocalFallback();
            InitializeForm();
            BuildSidebar();
            BuildContentArea();

            _refreshTimer = new System.Windows.Forms.Timer { Interval = 3000 };
            _refreshTimer.Tick += async (s, e) => await RefreshDataAsync();
            _refreshTimer.Start();

            _ = RefreshDataAsync();
            ShowView("dashboard");
        }

        private void InitializeForm()
        {
            Text = "PC Plus Endpoint Protection";
            Size = new Size(980, 640);
            MinimumSize = new Size(880, 560);
            StartPosition = FormStartPosition.CenterScreen;
            WindowState = FormWindowState.Maximized;
            BackColor = ContentBg;
            ForeColor = TextDark;
            Font = new Font("Segoe UI", 9.5f);
            DoubleBuffered = true;
            FormBorderStyle = FormBorderStyle.Sizable;
        }

        #region Sidebar

        private void BuildSidebar()
        {
            _sidebar = new Panel
            {
                Dock = DockStyle.Left, Width = 220,
                BackColor = SidebarBg
            };

            // Logo/brand area
            var brandPanel = new Panel
            {
                Dock = DockStyle.Top, Height = 70,
                BackColor = Color.Transparent
            };
            brandPanel.Paint += (s, e) =>
            {
                var g = e.Graphics;
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

                // Shield icon
                using var shieldBrush = new SolidBrush(AccentTeal);
                var shieldRect = new Rectangle(18, 18, 32, 36);
                var shieldPath = new GraphicsPath();
                shieldPath.AddArc(shieldRect.X, shieldRect.Y, 14, 14, 180, 90);
                shieldPath.AddArc(shieldRect.Right - 14, shieldRect.Y, 14, 14, 270, 90);
                shieldPath.AddLine(shieldRect.Right, shieldRect.Y + 7, shieldRect.Right, shieldRect.Y + shieldRect.Height / 2);
                shieldPath.AddLine(shieldRect.Right, shieldRect.Y + shieldRect.Height / 2,
                    shieldRect.X + shieldRect.Width / 2, shieldRect.Bottom);
                shieldPath.AddLine(shieldRect.X + shieldRect.Width / 2, shieldRect.Bottom,
                    shieldRect.X, shieldRect.Y + shieldRect.Height / 2);
                shieldPath.AddLine(shieldRect.X, shieldRect.Y + shieldRect.Height / 2, shieldRect.X, shieldRect.Y + 7);
                shieldPath.CloseFigure();
                g.FillPath(shieldBrush, shieldPath);

                // Checkmark on shield
                using var checkPen = new Pen(Color.White, 2.5f) { StartCap = LineCap.Round, EndCap = LineCap.Round };
                g.DrawLine(checkPen, 26, 37, 32, 43);
                g.DrawLine(checkPen, 32, 43, 42, 30);

                // App name
                using var brandFont = new Font("Segoe UI", 11, FontStyle.Bold);
                using var brandBrush = new SolidBrush(Color.White);
                g.DrawString("PC Plus Computing", brandFont, brandBrush, 56, 22);
                using var subFont = new Font("Segoe UI", 7.5f);
                using var subBrush = new SolidBrush(SidebarText);
                g.DrawString("ENDPOINT PROTECTION", subFont, subBrush, 58, 44);
            };

            // Navigation items
            var navPanel = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.Transparent,
                Padding = new Padding(0, 10, 0, 0)
            };

            int y = 0;
            AddNavItem(navPanel, "dashboard", "Dashboard", "\u2302", ref y);
            AddNavItem(navPanel, "scanner", "Scanner", "\u2714", ref y);
            AddNavItem(navPanel, "protection", "Real-Time Protection", "\u2616", ref y);
            AddNavItem(navPanel, "history", "Detection History", "\u2630", ref y);
            AddNavItem(navPanel, "advisor", "Trusted Advisor", "\u2605", ref y);
            y += 10; // spacer
            AddNavItem(navPanel, "system", "System Info", "\u2699", ref y);

            // Bottom status
            var statusPanel = new Panel
            {
                Dock = DockStyle.Bottom, Height = 55,
                BackColor = Color.FromArgb(18, 22, 28)
            };
            statusPanel.Paint += (s, e) =>
            {
                var g = e.Graphics;
                g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;
                using var font = new Font("Segoe UI", 8);
                using var brush = new SolidBrush(SidebarText);
                var status = _ipc.IsConnected ? "Service: Connected"
                    : _usingLocalFallback ? "Local Monitoring"
                    : "Service: Disconnected";
                var color = _ipc.IsConnected ? AccentGreen
                    : _usingLocalFallback ? AccentBlue : AccentRed;
                using var dotBrush = new SolidBrush(color);
                g.FillEllipse(dotBrush, 18, 18, 8, 8);
                g.DrawString(status, font, brush, 32, 14);
                var ver = typeof(MainForm).Assembly.GetName().Version?.ToString(3) ?? "4.3.0";
                g.DrawString($"v{ver}", font, brush, 32, 32);
            };

            _sidebar.Controls.Add(navPanel);
            _sidebar.Controls.Add(brandPanel);
            _sidebar.Controls.Add(statusPanel);
            Controls.Add(_sidebar);
        }

        private void AddNavItem(Panel parent, string id, string text, string icon, ref int y)
        {
            var btn = new Panel
            {
                Location = new Point(0, y), Size = new Size(220, 42),
                BackColor = Color.Transparent, Cursor = Cursors.Hand,
                Tag = id
            };
            btn.Paint += (s, e) =>
            {
                var g = e.Graphics;
                g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;
                var isActive = _currentView == (string)btn.Tag;

                if (isActive)
                {
                    using var activeBrush = new SolidBrush(SidebarActive);
                    g.FillRectangle(activeBrush, btn.ClientRectangle);
                    using var accentPen = new Pen(AccentTeal, 3);
                    g.DrawLine(accentPen, 0, 0, 0, btn.Height);
                }

                using var iconFont = new Font("Segoe UI Symbol", 12);
                using var textFont = new Font("Segoe UI", 10, isActive ? FontStyle.Bold : FontStyle.Regular);
                var textColor = isActive ? Color.White : SidebarText;
                using var brush = new SolidBrush(textColor);
                g.DrawString(icon, iconFont, brush, 18, 10);
                g.DrawString(text, textFont, brush, 46, 10);
            };
            btn.MouseEnter += (s, e) =>
            {
                if (_currentView != id)
                    btn.BackColor = SidebarHover;
            };
            btn.MouseLeave += (s, e) => btn.BackColor = Color.Transparent;
            btn.Click += (s, e) => ShowView(id);

            _navButtons[id] = btn;
            parent.Controls.Add(btn);
            y += 42;
        }

        /// <summary>Navigate to a specific view. Called externally by TrayContext.</summary>
        public void NavigateToView(string viewId) => ShowView(viewId);

        private void ShowView(string viewId)
        {
            _currentView = viewId;
            // Refresh all nav buttons
            foreach (var btn in _navButtons.Values)
                btn.Invalidate();

            // Clear content and show the selected view
            _contentArea.Controls.Clear();
            switch (viewId)
            {
                case "dashboard": BuildDashboardView(); break;
                case "scanner": BuildScannerView(); break;
                case "protection": BuildProtectionView(); break;
                case "history": BuildHistoryView(); break;
                case "advisor": BuildAdvisorView(); break;
                case "system": BuildSystemView(); break;
            }
        }

        #endregion

        #region Content Area

        private void BuildContentArea()
        {
            _contentArea = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = ContentBg,
                Padding = new Padding(24),
                AutoScroll = true
            };
            Controls.Add(_contentArea);
        }

        #endregion

        #region Dashboard View

        private void BuildDashboardView()
        {
            var title = CreatePageTitle("Dashboard");
            _contentArea.Controls.Add(title);

            // Status hero card
            var heroCard = CreateCard(new Point(24, 55), new Size(_contentArea.Width - 72, 110));
            heroCard.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            heroCard.Paint += (s, e) =>
            {
                var g = e.Graphics;
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

                var hasData = _health != null && (_health.CpuPercent > 0 || _health.RamPercent > 0);
                var statusColor = hasData ? AccentGreen : AccentOrange;
                var statusText = hasData ? "Your device is protected" : "Connecting to service...";

                // Large shield icon
                using var shieldBrush = new SolidBrush(statusColor);
                g.FillEllipse(shieldBrush, 20, 25, 56, 56);
                using var checkPen = new Pen(Color.White, 3f) { StartCap = LineCap.Round, EndCap = LineCap.Round };
                if (hasData)
                {
                    g.DrawLine(checkPen, 37, 53, 45, 61);
                    g.DrawLine(checkPen, 45, 61, 59, 42);
                }
                else
                {
                    using var waitFont = new Font("Segoe UI", 20, FontStyle.Bold);
                    using var waitBrush = new SolidBrush(Color.White);
                    g.DrawString("...", waitFont, waitBrush, 30, 30);
                }

                // Status text
                using var statusFont = new Font("Segoe UI", 18, FontStyle.Bold);
                using var statusBrushText = new SolidBrush(TextDark);
                g.DrawString(statusText, statusFont, statusBrushText, 90, 20);

                // Subtitle
                using var subFont = new Font("Segoe UI", 9.5f);
                using var subBrush = new SolidBrush(TextMuted);
                var sub = hasData
                    ? $"Last scan: {_securityResult?.ScanTime.ToString("MMM d, h:mm tt") ?? "Never"}     Score: {_securityResult?.TotalScore ?? 0}/100"
                    : "Waiting for data...";
                g.DrawString(sub, subFont, subBrush, 92, 56);

                // Uptime on right
                if (_health != null)
                {
                    var up = _health.Uptime;
                    var uptimeStr = $"Uptime: {(int)up.TotalDays}d {up.Hours}h {up.Minutes}m";
                    var uptimeSize = g.MeasureString(uptimeStr, subFont);
                    g.DrawString(uptimeStr, subFont, subBrush, heroCard.Width - uptimeSize.Width - 20, 56);
                }
            };
            _contentArea.Controls.Add(heroCard);

            // Stats cards row
            int cardY = 180;
            int cardW = (_contentArea.Width - 72 - 36) / 4; // 4 cards with spacing
            var cpuCard = CreateStatCard("CPU", _health?.CpuPercent ?? 0, "%", AccentBlue,
                new Point(24, cardY), new Size(cardW, 100));
            cpuCard.Anchor = AnchorStyles.Top | AnchorStyles.Left;

            var ramCard = CreateStatCard("Memory",
                _health?.RamPercent ?? 0, "%", AccentTeal,
                new Point(24 + cardW + 12, cardY), new Size(cardW, 100));
            ramCard.Anchor = AnchorStyles.Top | AnchorStyles.Left;

            var diskVal = _health?.Disks.FirstOrDefault()?.UsedPercent ?? 0;
            var diskCard = CreateStatCard("Disk", diskVal, "%", AccentOrange,
                new Point(24 + (cardW + 12) * 2, cardY), new Size(cardW, 100));
            diskCard.Anchor = AnchorStyles.Top | AnchorStyles.Left;

            var tempVal = _health?.CpuTempC ?? 0;
            var tempCard = CreateStatCard("Temp", tempVal, "C", AccentRed,
                new Point(24 + (cardW + 12) * 3, cardY), new Size(cardW, 100));
            tempCard.Anchor = AnchorStyles.Top | AnchorStyles.Left;

            _contentArea.Controls.AddRange(new Control[] { cpuCard, ramCard, diskCard, tempCard });

            // Bottom row: Processes + Quick Actions
            int bottomY = 295;
            int halfW = (_contentArea.Width - 72 - 12) / 2;

            var processCard = CreateCard(new Point(24, bottomY), new Size(halfW, 260));
            processCard.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            AddProcessList(processCard);
            _contentArea.Controls.Add(processCard);

            var quickCard = CreateCard(new Point(24 + halfW + 12, bottomY), new Size(halfW, 260));
            quickCard.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            AddQuickActions(quickCard);
            _contentArea.Controls.Add(quickCard);
        }

        private Panel CreateStatCard(string label, float value, string unit, Color color, Point loc, Size size)
        {
            var card = CreateCard(loc, size);
            card.Paint += (s, e) =>
            {
                var g = e.Graphics;
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

                // Label
                using var labelFont = new Font("Segoe UI", 9);
                using var labelBrush = new SolidBrush(TextMuted);
                g.DrawString(label, labelFont, labelBrush, 16, 12);

                // Value
                var displayVal = value > 0 ? $"{value:F0}" : "-";
                using var valFont = new Font("Segoe UI", 26, FontStyle.Bold);
                using var valBrush = new SolidBrush(TextDark);
                g.DrawString(displayVal, valFont, valBrush, 14, 30);

                // Unit
                var valSize = g.MeasureString(displayVal, valFont);
                using var unitFont = new Font("Segoe UI", 10);
                using var unitBrush = new SolidBrush(TextMuted);
                g.DrawString(unit, unitFont, unitBrush, 16 + valSize.Width, 45);

                // Progress bar at bottom
                int barY = card.Height - 14;
                int barW = card.Width - 32;
                using var bgPen = new Pen(Color.FromArgb(230, 233, 237), 4);
                bgPen.StartCap = LineCap.Round; bgPen.EndCap = LineCap.Round;
                g.DrawLine(bgPen, 16, barY, 16 + barW, barY);

                if (value > 0)
                {
                    var fillW = (int)(barW * Math.Min(value / 100f, 1f));
                    var barColor = value > 90 ? AccentRed : value > 75 ? AccentOrange : color;
                    using var fillPen = new Pen(barColor, 4);
                    fillPen.StartCap = LineCap.Round; fillPen.EndCap = LineCap.Round;
                    if (fillW > 2) g.DrawLine(fillPen, 16, barY, 16 + fillW, barY);
                }
            };
            return card;
        }

        private void AddProcessList(Panel card)
        {
            card.Paint += (s, e) =>
            {
                var g = e.Graphics;
                g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

                using var titleFont = new Font("Segoe UI", 11, FontStyle.Bold);
                using var titleBrush = new SolidBrush(TextDark);
                g.DrawString("Top Processes", titleFont, titleBrush, 16, 12);

                if (_health?.TopProcesses == null || _health.TopProcesses.Count == 0)
                {
                    using var emptyFont = new Font("Segoe UI", 9);
                    using var emptyBrush = new SolidBrush(TextMuted);
                    g.DrawString("No process data available", emptyFont, emptyBrush, 16, 44);
                    return;
                }

                using var monoFont = new Font("Cascadia Mono", 8.5f);
                using var headerFont = new Font("Segoe UI", 8, FontStyle.Bold);
                using var headerBrush = new SolidBrush(TextMuted);

                // Column headers
                int y = 40;
                g.DrawString("Process", headerFont, headerBrush, 16, y);
                g.DrawString("CPU", headerFont, headerBrush, card.Width - 160, y);
                g.DrawString("Memory", headerFont, headerBrush, card.Width - 90, y);
                y += 20;

                using var linePen = new Pen(CardBorder);
                g.DrawLine(linePen, 16, y - 2, card.Width - 16, y - 2);

                foreach (var proc in _health.TopProcesses.Take(8))
                {
                    var cpuColor = proc.CpuPercent > 50 ? AccentRed : proc.CpuPercent > 20 ? AccentOrange : TextDark;
                    using var nameBrush = new SolidBrush(TextDark);
                    using var cpuBrush = new SolidBrush(cpuColor);
                    using var memBrush = new SolidBrush(TextMuted);

                    var name = proc.Name.Length > 22 ? proc.Name[..22] + "..." : proc.Name;
                    g.DrawString(name, monoFont, nameBrush, 16, y);
                    g.DrawString($"{proc.CpuPercent:F1}%", monoFont, cpuBrush, card.Width - 160, y);
                    g.DrawString($"{proc.MemoryMB:F0} MB", monoFont, memBrush, card.Width - 90, y);
                    y += 22;
                }
            };
        }

        private void AddQuickActions(Panel card)
        {
            var titleLabel = new Label
            {
                Text = "Quick Actions", Font = new Font("Segoe UI", 11, FontStyle.Bold),
                ForeColor = TextDark, BackColor = Color.Transparent,
                Location = new Point(16, 12), AutoSize = true
            };
            card.Controls.Add(titleLabel);

            var actions = new (string text, string desc, Color color, Func<Task> action)[]
            {
                ("Run Security Scan", "Scan for vulnerabilities and misconfigurations", AccentTeal, async () =>
                {
                    if (_ipc.IsConnected && !_usingLocalFallback)
                    {
                        await Task.Run(() => _ipc.RunSecurityScanAsync());
                        await Task.Delay(3000);
                    }
                    else
                    {
                        _securityResult = await _localFallback.RunSecurityScanAsync();
                    }
                    await RefreshDataAsync();
                    ShowView("scanner");
                }),
                ("Fix My Computer", "Clear temp files, flush DNS, reset network", AccentBlue, async () =>
                {
                    var confirm = MessageBox.Show(
                        "This will:\n- Clear temporary files\n- Flush DNS cache\n" +
                        "- Reset Winsock catalog\n- Refresh icons\n- Restart Explorer\n\nContinue?",
                        "Fix My Computer", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
                    if (confirm != DialogResult.Yes) return;

                    if (_ipc.IsConnected && !_usingLocalFallback)
                    {
                        var response = await Task.Run(() => _ipc.SendModuleCommandAsync("maintenance", "RunMaintenance",
                            new() { ["action"] = "fixmypc" }));
                        if (response.Success)
                            MessageBox.Show("Repair complete!", "Fix My Computer",
                                MessageBoxButtons.OK, MessageBoxIcon.Information);
                        else
                            MessageBox.Show($"Error: {response.Message}", "Fix My Computer",
                                MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    }
                    else
                    {
                        var result = await _localFallback.RunFixMyComputerAsync();
                        MessageBox.Show("Repair complete!\n\n" + result, "Fix My Computer",
                            MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
                }),
                ("Take Screenshot", "Save a screenshot to Pictures folder", AccentGreen, async () =>
                {
                    await Task.CompletedTask;
                    TakeScreenshot();
                })
            };

            int y = 44;
            foreach (var (text, desc, color, action) in actions)
            {
                var btn = new Panel
                {
                    Location = new Point(16, y), Size = new Size(card.Width - 32, 58),
                    BackColor = Color.FromArgb(248, 249, 250), Cursor = Cursors.Hand
                };
                btn.Paint += (s, e) =>
                {
                    var g = e.Graphics;
                    g.SmoothingMode = SmoothingMode.AntiAlias;
                    g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

                    // Rounded border
                    using var borderPen = new Pen(CardBorder);
                    using var path = RoundedRect(new Rectangle(0, 0, btn.Width - 1, btn.Height - 1), 6);
                    g.DrawPath(borderPen, path);

                    // Color dot
                    using var dotBrush = new SolidBrush(color);
                    g.FillEllipse(dotBrush, 14, 18, 10, 10);

                    // Text
                    using var nameFont = new Font("Segoe UI", 10, FontStyle.Bold);
                    using var descFont = new Font("Segoe UI", 8);
                    using var nameBrush = new SolidBrush(TextDark);
                    using var descBrush = new SolidBrush(TextMuted);
                    g.DrawString(text, nameFont, nameBrush, 32, 8);
                    g.DrawString(desc, descFont, descBrush, 32, 30);

                    // Arrow
                    using var arrowFont = new Font("Segoe UI", 12);
                    g.DrawString("\u203A", arrowFont, descBrush, btn.Width - 24, 14);
                };
                btn.MouseEnter += (s, e) => btn.BackColor = Color.FromArgb(240, 243, 246);
                btn.MouseLeave += (s, e) => btn.BackColor = Color.FromArgb(248, 249, 250);
                btn.Click += async (s, e) =>
                {
                    try { await action(); }
                    catch { }
                };
                card.Controls.Add(btn);
                y += 66;
            }
        }

        #endregion

        #region Scanner View

        private void BuildScannerView()
        {
            var title = CreatePageTitle("Scanner");
            _contentArea.Controls.Add(title);

            // Score card
            var scoreCard = CreateCard(new Point(24, 55), new Size(_contentArea.Width - 72, 120));
            scoreCard.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            scoreCard.Paint += (s, e) =>
            {
                var g = e.Graphics;
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

                var score = _securityResult?.TotalScore ?? 0;
                var grade = _securityResult?.Grade ?? "?";
                var gradeColor = grade switch
                {
                    "A" => AccentGreen, "B" => AccentBlue,
                    "C" => AccentOrange, _ => AccentRed
                };

                // Big grade circle
                using var circleBrush = new SolidBrush(gradeColor);
                g.FillEllipse(circleBrush, 20, 20, 70, 70);
                using var gradeFont = new Font("Segoe UI", 28, FontStyle.Bold);
                using var whiteBrush = new SolidBrush(Color.White);
                var gradeSize = g.MeasureString(grade, gradeFont);
                g.DrawString(grade, gradeFont, whiteBrush,
                    20 + (70 - gradeSize.Width) / 2, 20 + (70 - gradeSize.Height) / 2);

                // Score text
                using var scoreFont = new Font("Segoe UI", 24, FontStyle.Bold);
                using var scoreBrush = new SolidBrush(TextDark);
                g.DrawString($"{score}/100", scoreFont, scoreBrush, 108, 18);

                using var descFont = new Font("Segoe UI", 9.5f);
                using var descBrush = new SolidBrush(TextMuted);
                var passCount = _securityResult?.Checks.Count(c => c.Passed) ?? 0;
                var totalCount = _securityResult?.Checks.Count ?? 0;
                g.DrawString($"{passCount} of {totalCount} checks passed", descFont, descBrush, 110, 58);

                if (_securityResult != null)
                    g.DrawString($"Last scan: {_securityResult.ScanTime:MMM d, h:mm tt}", descFont, descBrush, 110, 78);
            };
            _contentArea.Controls.Add(scoreCard);

            // Scan button
            var scanBtn = CreateActionButton("Run Full Scan", AccentTeal, new Point(24, 188), new Size(180, 40));
            scanBtn.Click += async (s, e) =>
            {
                scanBtn.Enabled = false;
                scanBtn.Text = "Scanning...";
                if (_ipc.IsConnected && !_usingLocalFallback)
                {
                    await Task.Run(() => _ipc.RunSecurityScanAsync());
                    await Task.Delay(3000);
                }
                else
                {
                    _securityResult = await _localFallback.RunSecurityScanAsync();
                }
                await RefreshDataAsync();
                scanBtn.Text = "Run Full Scan";
                scanBtn.Enabled = true;
                ShowView("scanner");
            };
            _contentArea.Controls.Add(scanBtn);

            // Checks list
            if (_securityResult?.Checks != null)
            {
                int y = 245;
                foreach (var check in _securityResult.Checks.OrderBy(c => c.Passed).ThenBy(c => c.Category))
                {
                    var checkCard = CreateCard(new Point(24, y), new Size(_contentArea.Width - 72, 52));
                    checkCard.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
                    var localCheck = check; // capture for closure
                    checkCard.Paint += (s, e) =>
                    {
                        var g = e.Graphics;
                        g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

                        // Status icon
                        var iconColor = localCheck.Passed ? AccentGreen : AccentRed;
                        var iconText = localCheck.Passed ? "\u2713" : "\u2717";
                        using var iconFont = new Font("Segoe UI", 13, FontStyle.Bold);
                        using var iconBrush = new SolidBrush(iconColor);
                        g.DrawString(iconText, iconFont, iconBrush, 12, 10);

                        // Name
                        using var nameFont = new Font("Segoe UI", 9.5f, localCheck.Passed ? FontStyle.Regular : FontStyle.Bold);
                        using var nameBrush = new SolidBrush(TextDark);
                        g.DrawString(localCheck.Name, nameFont, nameBrush, 40, 6);

                        // Detail/recommendation
                        using var detailFont = new Font("Segoe UI", 8);
                        var detailColor = localCheck.Passed ? TextMuted : AccentOrange;
                        using var detailBrush = new SolidBrush(detailColor);
                        var detail = localCheck.Passed ? localCheck.Detail : (localCheck.Recommendation ?? localCheck.Detail);
                        if (detail.Length > 80) detail = detail[..80] + "...";
                        g.DrawString(detail, detailFont, detailBrush, 40, 28);

                        // Category badge
                        using var catFont = new Font("Segoe UI", 7.5f);
                        using var catBrush = new SolidBrush(TextMuted);
                        var catSize = g.MeasureString(localCheck.Category, catFont);
                        g.DrawString(localCheck.Category, catFont, catBrush, checkCard.Width - catSize.Width - 16, 16);
                    };
                    _contentArea.Controls.Add(checkCard);
                    y += 58;
                }
            }
        }

        #endregion

        #region Protection View

        private void BuildProtectionView()
        {
            var title = CreatePageTitle("Real-Time Protection");
            _contentArea.Controls.Add(title);

            if (_serviceStatus?.Modules == null || _serviceStatus.Modules.Count == 0)
            {
                var noData = new Label
                {
                    Text = "Waiting for service data...",
                    Font = new Font("Segoe UI", 11),
                    ForeColor = TextMuted,
                    Location = new Point(24, 60), AutoSize = true
                };
                _contentArea.Controls.Add(noData);
                return;
            }

            int y = 55;
            foreach (var module in _serviceStatus.Modules)
            {
                var moduleCard = CreateCard(new Point(24, y), new Size(_contentArea.Width - 72, 65));
                moduleCard.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
                var localMod = module;
                moduleCard.Paint += (s, e) =>
                {
                    var g = e.Graphics;
                    g.SmoothingMode = SmoothingMode.AntiAlias;
                    g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

                    // Status indicator
                    var statusColor = localMod.IsRunning ? AccentGreen : AccentRed;
                    using var dotBrush = new SolidBrush(statusColor);
                    g.FillEllipse(dotBrush, 16, 22, 16, 16);

                    // Module name
                    using var nameFont = new Font("Segoe UI", 11, FontStyle.Bold);
                    using var nameBrush = new SolidBrush(TextDark);
                    g.DrawString(localMod.ModuleName, nameFont, nameBrush, 42, 8);

                    // Status text
                    using var statusFont = new Font("Segoe UI", 9);
                    using var statusBrush = new SolidBrush(TextMuted);
                    var statusText = localMod.IsRunning
                        ? localMod.StatusText ?? "Running"
                        : $"Stopped (requires {localMod.RequiredTier})";
                    g.DrawString(statusText, statusFont, statusBrush, 42, 34);

                    // Toggle-style indicator on right
                    int toggleX = moduleCard.Width - 70;
                    int toggleY = 20;
                    using var togglePath = RoundedRect(new Rectangle(toggleX, toggleY, 48, 22), 11);
                    using var toggleBgBrush = new SolidBrush(localMod.IsRunning ? AccentGreen : Color.FromArgb(200, 200, 200));
                    g.FillPath(toggleBgBrush, togglePath);
                    int knobX = localMod.IsRunning ? toggleX + 28 : toggleX + 4;
                    using var knobBrush = new SolidBrush(Color.White);
                    g.FillEllipse(knobBrush, knobX, toggleY + 3, 16, 16);
                };
                _contentArea.Controls.Add(moduleCard);
                y += 73;
            }
        }

        #endregion

        #region History View

        private void BuildHistoryView()
        {
            var title = CreatePageTitle("Detection History");
            _contentArea.Controls.Add(title);

            if (_alerts.Count == 0)
            {
                var emptyCard = CreateCard(new Point(24, 55), new Size(_contentArea.Width - 72, 120));
                emptyCard.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
                emptyCard.Paint += (s, e) =>
                {
                    var g = e.Graphics;
                    g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

                    using var iconFont = new Font("Segoe UI", 28);
                    using var iconBrush = new SolidBrush(AccentGreen);
                    g.DrawString("\u2713", iconFont, iconBrush, 30, 25);

                    using var msgFont = new Font("Segoe UI", 14);
                    using var msgBrush = new SolidBrush(TextDark);
                    g.DrawString("No threats detected", msgFont, msgBrush, 80, 28);

                    using var subFont = new Font("Segoe UI", 9.5f);
                    using var subBrush = new SolidBrush(TextMuted);
                    g.DrawString("Your device is clean. Keep real-time protection enabled.", subFont, subBrush, 80, 60);
                };
                _contentArea.Controls.Add(emptyCard);
                return;
            }

            int y = 55;
            foreach (var alert in _alerts.Take(20))
            {
                var alertCard = CreateCard(new Point(24, y), new Size(_contentArea.Width - 72, 60));
                alertCard.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
                var localAlert = alert;
                alertCard.Paint += (s, e) =>
                {
                    var g = e.Graphics;
                    g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

                    var sevColor = localAlert.Severity switch
                    {
                        AlertSeverity.Emergency => AccentRed,
                        AlertSeverity.Critical => AccentRed,
                        AlertSeverity.Warning => AccentOrange,
                        _ => AccentBlue
                    };

                    // Severity bar on left
                    using var barBrush = new SolidBrush(sevColor);
                    g.FillRectangle(barBrush, 0, 0, 4, alertCard.Height);

                    // Title
                    using var titleFont = new Font("Segoe UI", 10, FontStyle.Bold);
                    using var titleBrush = new SolidBrush(TextDark);
                    g.DrawString(localAlert.Title, titleFont, titleBrush, 16, 8);

                    // Message
                    using var msgFont = new Font("Segoe UI", 8.5f);
                    using var msgBrush = new SolidBrush(TextMuted);
                    var msg = localAlert.Message.Length > 80 ? localAlert.Message[..80] + "..." : localAlert.Message;
                    g.DrawString(msg, msgFont, msgBrush, 16, 32);

                    // Timestamp
                    using var timeFont = new Font("Segoe UI", 7.5f);
                    var timeStr = localAlert.Timestamp.ToString("MMM d, h:mm tt");
                    var timeSize = g.MeasureString(timeStr, timeFont);
                    g.DrawString(timeStr, timeFont, msgBrush, alertCard.Width - timeSize.Width - 16, 12);
                };
                _contentArea.Controls.Add(alertCard);
                y += 68;
            }
        }

        #endregion

        #region Trusted Advisor View

        private void BuildAdvisorView()
        {
            var title = CreatePageTitle("Trusted Advisor");
            _contentArea.Controls.Add(title);

            // Score gauge card - Malwarebytes-style large gauge
            var gaugeCard = CreateCard(new Point(24, 55), new Size(_contentArea.Width - 72, 220));
            gaugeCard.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            gaugeCard.Paint += (s, e) =>
            {
                var g = e.Graphics;
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

                var score = _securityResult?.TotalScore ?? 0;
                var grade = _securityResult?.Grade ?? "?";

                // Large arc gauge (centered)
                int gaugeSize = 160;
                int gaugeX = (gaugeCard.Width - gaugeSize) / 2;
                int gaugeY = 15;
                var arcRect = new Rectangle(gaugeX, gaugeY, gaugeSize, gaugeSize);

                float startAngle = 150;
                float sweepAngle = 240;
                float valueSweep = score / 100f * sweepAngle;

                // Background arc
                using var bgPen = new Pen(Color.FromArgb(230, 233, 237), 12);
                bgPen.StartCap = LineCap.Round; bgPen.EndCap = LineCap.Round;
                g.DrawArc(bgPen, arcRect, startAngle, sweepAngle);

                // Value arc with gradient
                if (valueSweep > 0)
                {
                    var gaugeColor = score >= 80 ? AccentGreen : score >= 60 ? AccentOrange : AccentRed;
                    using var valuePen = new Pen(gaugeColor, 12);
                    valuePen.StartCap = LineCap.Round; valuePen.EndCap = LineCap.Round;
                    g.DrawArc(valuePen, arcRect, startAngle, valueSweep);
                }

                // Score in center
                using var scoreFont = new Font("Segoe UI", 36, FontStyle.Bold);
                using var scoreBrush = new SolidBrush(TextDark);
                var scoreStr = score > 0 ? score.ToString() : "-";
                var scoreSize = g.MeasureString(scoreStr, scoreFont);
                g.DrawString(scoreStr, scoreFont, scoreBrush,
                    gaugeX + (gaugeSize - scoreSize.Width) / 2,
                    gaugeY + (gaugeSize - scoreSize.Height) / 2 - 8);

                // "out of 100" text
                using var outOfFont = new Font("Segoe UI", 9);
                using var outOfBrush = new SolidBrush(TextMuted);
                var outStr = "out of 100";
                var outSize = g.MeasureString(outStr, outOfFont);
                g.DrawString(outStr, outOfFont, outOfBrush,
                    gaugeX + (gaugeSize - outSize.Width) / 2,
                    gaugeY + gaugeSize / 2 + scoreSize.Height / 2 - 16);

                // Status text below gauge
                using var statusFont = new Font("Segoe UI", 12);
                var statusText = score >= 80 ? "Your device is well-protected"
                    : score >= 60 ? "Some improvements recommended"
                    : score > 0 ? "Action needed to improve security" : "Run a scan to get your score";
                var statusColor = score >= 80 ? AccentGreen : score >= 60 ? AccentOrange : score > 0 ? AccentRed : TextMuted;
                using var statusBrush2 = new SolidBrush(statusColor);
                var statusSize = g.MeasureString(statusText, statusFont);
                g.DrawString(statusText, statusFont, statusBrush2,
                    (gaugeCard.Width - statusSize.Width) / 2, 185);
            };
            _contentArea.Controls.Add(gaugeCard);

            // Recommendations
            if (_securityResult?.Checks != null)
            {
                var failedChecks = _securityResult.Checks.Where(c => !c.Passed).ToList();
                if (failedChecks.Count > 0)
                {
                    var recTitle = new Label
                    {
                        Text = "Recommendations",
                        Font = new Font("Segoe UI", 12, FontStyle.Bold),
                        ForeColor = TextDark,
                        Location = new Point(24, 290), AutoSize = true
                    };
                    _contentArea.Controls.Add(recTitle);

                    int y = 318;
                    foreach (var check in failedChecks.Take(8))
                    {
                        var recCard = CreateCard(new Point(24, y), new Size(_contentArea.Width - 72, 50));
                        recCard.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
                        var localCheck = check;
                        recCard.Paint += (s, e) =>
                        {
                            var g = e.Graphics;
                            g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

                            using var warnBrush = new SolidBrush(AccentOrange);
                            g.FillRectangle(warnBrush, 0, 0, 4, recCard.Height);

                            using var nameFont = new Font("Segoe UI", 9.5f, FontStyle.Bold);
                            using var nameBrush = new SolidBrush(TextDark);
                            g.DrawString(localCheck.Name, nameFont, nameBrush, 16, 6);

                            using var recFont = new Font("Segoe UI", 8);
                            using var recBrush = new SolidBrush(AccentOrange);
                            var rec = localCheck.Recommendation ?? localCheck.Detail;
                            if (rec.Length > 90) rec = rec[..90] + "...";
                            g.DrawString(rec, recFont, recBrush, 16, 28);
                        };
                        _contentArea.Controls.Add(recCard);
                        y += 56;
                    }
                }
            }
        }

        #endregion

        #region System Info View

        private void BuildSystemView()
        {
            var title = CreatePageTitle("System Information");
            _contentArea.Controls.Add(title);

            var copyBtn = CreateActionButton("Copy All", AccentBlue, new Point(_contentArea.Width - 140, 10), new Size(90, 32));
            copyBtn.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            _contentArea.Controls.Add(copyBtn);

            // Collect system info
            var items = new List<(string category, string key, string value)>();
            items.Add(("System", "Computer Name", Environment.MachineName));
            items.Add(("System", "User", $"{Environment.UserDomainName}\\{Environment.UserName}"));
            items.Add(("System", "OS", GetFriendlyOsVersion()));
            items.Add(("System", "Architecture", Environment.Is64BitOperatingSystem ? "64-bit" : "32-bit"));
            items.Add(("System", ".NET Runtime", System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription));
            items.Add(("System", "Local IP", GetLocalIpAddress()));
            items.Add(("System", "Public IP", _cachedPublicIp ?? "Loading..."));

            if (_health != null)
            {
                items.Add(("Health", "CPU Usage", $"{_health.CpuPercent:F0}%"));
                items.Add(("Health", "RAM Usage", $"{_health.RamUsedGB:F1} / {_health.RamTotalGB:F1} GB ({_health.RamPercent:F0}%)"));
                items.Add(("Health", "CPU Temperature", _health.CpuTempC > 0 ? $"{_health.CpuTempC:F0} C" : "N/A"));
                items.Add(("Health", "GPU Temperature", _health.GpuTempC > 0 ? $"{_health.GpuTempC:F0} C" : "N/A"));
                items.Add(("Health", "Uptime", $"{(int)_health.Uptime.TotalDays}d {_health.Uptime.Hours}h {_health.Uptime.Minutes}m"));
                items.Add(("Health", "Processes", _health.ProcessCount.ToString()));
                items.Add(("Health", "Network", $"Up: {_health.NetworkSentKBps:F0} KB/s  Down: {_health.NetworkRecvKBps:F0} KB/s"));

                foreach (var disk in _health.Disks)
                    items.Add(("Disks", $"Drive {disk.Name}", $"{disk.FreeGB:F0} GB free / {disk.TotalGB:F0} GB ({disk.UsedPercent:F0}% used)"));
            }

            // Load WMI info and public IP async
            _ = Task.Run(async () =>
            {
                var hwItems = GetHardwareInfo();
                await FetchPublicIpAsync();
                if (InvokeRequired && !IsDisposed)
                    Invoke(new Action(() =>
                    {
                        // Rebuild items with public IP resolved
                        var updatedItems = new List<(string category, string key, string value)>();
                        updatedItems.Add(("System", "Computer Name", Environment.MachineName));
                        updatedItems.Add(("System", "User", $"{Environment.UserDomainName}\\{Environment.UserName}"));
                        updatedItems.Add(("System", "OS", GetFriendlyOsVersion()));
                        updatedItems.Add(("System", "Architecture", Environment.Is64BitOperatingSystem ? "64-bit" : "32-bit"));
                        updatedItems.Add(("System", ".NET Runtime", System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription));
                        updatedItems.Add(("System", "Local IP", GetLocalIpAddress()));
                        updatedItems.Add(("System", "Public IP", _cachedPublicIp ?? "N/A"));
                        if (_health != null)
                        {
                            updatedItems.Add(("Health", "CPU Usage", $"{_health.CpuPercent:F0}%"));
                            updatedItems.Add(("Health", "RAM Usage", $"{_health.RamUsedGB:F1} / {_health.RamTotalGB:F1} GB ({_health.RamPercent:F0}%)"));
                            updatedItems.Add(("Health", "CPU Temperature", _health.CpuTempC > 0 ? $"{_health.CpuTempC:F0} C" : "N/A"));
                            updatedItems.Add(("Health", "GPU Temperature", _health.GpuTempC > 0 ? $"{_health.GpuTempC:F0} C" : "N/A"));
                            updatedItems.Add(("Health", "Uptime", $"{(int)_health.Uptime.TotalDays}d {_health.Uptime.Hours}h {_health.Uptime.Minutes}m"));
                            updatedItems.Add(("Health", "Processes", _health.ProcessCount.ToString()));
                            updatedItems.Add(("Health", "Network", $"Up: {_health.NetworkSentKBps:F0} KB/s  Down: {_health.NetworkRecvKBps:F0} KB/s"));
                            foreach (var disk in _health.Disks)
                                updatedItems.Add(("Disks", $"Drive {disk.Name}", $"{disk.FreeGB:F0} GB free / {disk.TotalGB:F0} GB ({disk.UsedPercent:F0}% used)"));
                        }
                        AddSystemInfoRows(updatedItems.Concat(hwItems).ToList(), copyBtn);
                    }));
            });

            // Show what we have immediately
            AddSystemInfoRows(items, copyBtn);
        }

        private void AddSystemInfoRows(List<(string category, string key, string value)> items, Button copyBtn)
        {
            // Remove old rows (keep title and copy button)
            var toRemove = _contentArea.Controls.OfType<Panel>()
                .Where(p => p.Tag?.ToString() == "sysrow").ToList();
            foreach (var p in toRemove) { _contentArea.Controls.Remove(p); p.Dispose(); }

            int y = 55;
            string lastCategory = "";

            foreach (var (category, key, value) in items)
            {
                if (category != lastCategory)
                {
                    var catLabel = new Label
                    {
                        Text = category, Font = new Font("Segoe UI", 10, FontStyle.Bold),
                        ForeColor = AccentTeal, BackColor = Color.Transparent,
                        Location = new Point(24, y), AutoSize = true
                    };
                    var catPanel = new Panel
                    {
                        Location = new Point(24, y), Size = new Size(_contentArea.Width - 72, 28),
                        BackColor = Color.Transparent, Tag = "sysrow"
                    };
                    catPanel.Controls.Add(new Label
                    {
                        Text = category, Font = new Font("Segoe UI", 10, FontStyle.Bold),
                        ForeColor = AccentTeal, BackColor = Color.Transparent,
                        Location = new Point(0, 4), AutoSize = true
                    });
                    _contentArea.Controls.Add(catPanel);
                    lastCategory = category;
                    y += 30;
                }

                var row = CreateCard(new Point(24, y), new Size(_contentArea.Width - 72, 30));
                row.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
                row.Tag = "sysrow";
                var localKey = key;
                var localVal = value;
                row.Paint += (s, e) =>
                {
                    var g = e.Graphics;
                    g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;
                    using var keyFont = new Font("Segoe UI", 9, FontStyle.Bold);
                    using var valFont = new Font("Segoe UI", 9);
                    using var keyBrush = new SolidBrush(TextDark);
                    using var valBrush = new SolidBrush(TextMuted);
                    g.DrawString(localKey, keyFont, keyBrush, 12, 5);
                    g.DrawString(localVal, valFont, valBrush, 220, 5);
                };
                _contentArea.Controls.Add(row);
                y += 34;
            }

            // Wire up copy button
            copyBtn.Click -= CopyAllHandler;
            _sysInfoItems = items;
            copyBtn.Click += CopyAllHandler;
        }

        private List<(string category, string key, string value)>? _sysInfoItems;

        private void CopyAllHandler(object? sender, EventArgs e)
        {
            if (_sysInfoItems == null) return;
            var text = string.Join("\n", _sysInfoItems.Select(i => $"{i.key}: {i.value}"));
            Clipboard.SetText(text);
            if (sender is Button btn)
            {
                btn.Text = "Copied!";
                _ = Task.Delay(1500).ContinueWith(_ =>
                {
                    if (!IsDisposed) Invoke(new Action(() => btn.Text = "Copy All"));
                });
            }
        }

        #endregion

        #region Data Refresh

        private async Task RefreshDataAsync()
        {
            try
            {
                bool gotServiceData = false;

                // Try IPC first
                if (!_ipc.IsConnected)
                {
                    try { await Task.Run(() => _ipc.ConnectAsync(3000)); }
                    catch { }
                }

                if (_ipc.IsConnected)
                {
                    // Fetch health from service
                    var healthResp = await Task.Run(() => _ipc.GetHealthSnapshotAsync());
                    if (healthResp.Success)
                    {
                        _health = healthResp.GetData<HealthSnapshot>();
                        if (_health != null) gotServiceData = true;
                    }

                    // Fetch security
                    var secResp = await Task.Run(() => _ipc.GetSecurityScoreAsync());
                    if (secResp.Success)
                        _securityResult = secResp.GetData<SecurityScanResult>();

                    // Fetch service status
                    var statusResp = await Task.Run(() => _ipc.GetServiceStatusAsync());
                    if (statusResp.Success)
                        _serviceStatus = statusResp.GetData<ServiceStatusReport>();

                    // Fetch alerts
                    var alertResp = await Task.Run(() => _ipc.GetRecentAlertsAsync(20));
                    if (alertResp.Success)
                    {
                        var alerts = alertResp.GetData<List<Alert>>();
                        if (alerts != null) _alerts = alerts;
                    }
                }

                // Fallback: use local monitoring if service didn't provide health data
                if (!gotServiceData || _health == null)
                {
                    if (!_usingLocalFallback)
                    {
                        _usingLocalFallback = true;
                        _localFallback.Start();
                    }
                    _health = _localFallback.CurrentHealth;

                    // Use local security scan result if no service result
                    if (_securityResult == null)
                        _securityResult = _localFallback.LastSecurityScan;
                }

                // Refresh current view
                if (!IsDisposed && InvokeRequired)
                    Invoke(new Action(() =>
                    {
                        // Invalidate sidebar status
                        foreach (var ctrl in _sidebar.Controls)
                            if (ctrl is Panel p) p.Invalidate();

                        // Refresh the currently displayed view
                        ShowView(_currentView);
                    }));
            }
            catch { }
        }

        #endregion

        #region Helpers

        private Label CreatePageTitle(string text)
        {
            return new Label
            {
                Text = text, AutoSize = true,
                Font = new Font("Segoe UI", 16, FontStyle.Bold),
                ForeColor = TextDark, Location = new Point(24, 14),
                BackColor = Color.Transparent
            };
        }

        private Panel CreateCard(Point location, Size size)
        {
            var card = new Panel
            {
                Location = location, Size = size,
                BackColor = CardBg
            };
            card.Paint += (s, e) =>
            {
                var g = e.Graphics;
                g.SmoothingMode = SmoothingMode.AntiAlias;
                using var pen = new Pen(CardBorder);
                using var path = RoundedRect(new Rectangle(0, 0, card.Width - 1, card.Height - 1), 8);
                g.DrawPath(pen, path);
            };
            return card;
        }

        private Button CreateActionButton(string text, Color color, Point location, Size size)
        {
            var btn = new Button
            {
                Text = text, Location = location, Size = size,
                FlatStyle = FlatStyle.Flat,
                BackColor = color, ForeColor = Color.White,
                Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
                Cursor = Cursors.Hand
            };
            btn.FlatAppearance.BorderSize = 0;
            return btn;
        }

        private static GraphicsPath RoundedRect(Rectangle rect, int radius)
        {
            var path = new GraphicsPath();
            int d = radius * 2;
            path.AddArc(rect.X, rect.Y, d, d, 180, 90);
            path.AddArc(rect.Right - d, rect.Y, d, d, 270, 90);
            path.AddArc(rect.Right - d, rect.Bottom - d, d, d, 0, 90);
            path.AddArc(rect.X, rect.Bottom - d, d, d, 90, 90);
            path.CloseFigure();
            return path;
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
                bitmap.Save(filepath, System.Drawing.Imaging.ImageFormat.Png);

                MessageBox.Show($"Screenshot saved to:\n{filepath}", "Screenshot Saved",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);

                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                { FileName = filepath, UseShellExecute = true });
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Screenshot failed: {ex.Message}", "Screenshot",
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
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
            return "N/A";
        }

        private string? _cachedPublicIp;

        private async Task FetchPublicIpAsync()
        {
            if (_cachedPublicIp != null) return;
            try
            {
                using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
                _cachedPublicIp = (await client.GetStringAsync("https://api.ipify.org")).Trim();
            }
            catch { _cachedPublicIp = "N/A"; }
        }

        private static List<(string, string, string)> GetHardwareInfo()
        {
            var items = new List<(string, string, string)>();
            try
            {
                using var cpuSearch = new ManagementObjectSearcher("SELECT Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed FROM Win32_Processor");
                foreach (var obj in cpuSearch.Get())
                {
                    items.Add(("Hardware", "CPU", obj["Name"]?.ToString()?.Trim() ?? "Unknown"));
                    items.Add(("Hardware", "Cores / Threads", $"{obj["NumberOfCores"]} / {obj["NumberOfLogicalProcessors"]}"));
                    items.Add(("Hardware", "Max Clock", $"{obj["MaxClockSpeed"]} MHz"));
                }

                using var ramSearch = new ManagementObjectSearcher("SELECT TotalPhysicalMemory FROM Win32_ComputerSystem");
                foreach (var obj in ramSearch.Get())
                {
                    var totalBytes = Convert.ToInt64(obj["TotalPhysicalMemory"]);
                    items.Add(("Hardware", "Total RAM", $"{totalBytes / 1024 / 1024 / 1024.0:F1} GB"));
                }

                using var gpuSearch = new ManagementObjectSearcher("SELECT Name, AdapterRAM FROM Win32_VideoController");
                foreach (var obj in gpuSearch.Get())
                {
                    var vram = Convert.ToInt64(obj["AdapterRAM"] ?? 0);
                    var vramStr = vram > 0 ? $" ({vram / 1024 / 1024} MB)" : "";
                    items.Add(("Hardware", "GPU", $"{obj["Name"]}{vramStr}"));
                }

                using var netSearch = new ManagementObjectSearcher(
                    "SELECT Description, MACAddress, Speed FROM Win32_NetworkAdapter WHERE NetEnabled=True AND PhysicalAdapter=True");
                foreach (var obj in netSearch.Get())
                {
                    var speed = Convert.ToInt64(obj["Speed"] ?? 0);
                    var speedStr = speed > 0 ? $" ({speed / 1000000} Mbps)" : "";
                    items.Add(("Network", obj["Description"]?.ToString() ?? "Adapter", $"MAC: {obj["MACAddress"]}{speedStr}"));
                }
            }
            catch { }
            return items;
        }

        #endregion

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            _refreshTimer.Stop();
            _refreshTimer.Dispose();
            _localFallback.Dispose();
            base.OnFormClosing(e);
        }
    }
}
