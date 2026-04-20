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
            BuildContentArea();
            BuildSidebar();

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
            AddNavItem(navPanel, "lockdown", "Lockdown Mode", "\u26A0", ref y);
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
                case "lockdown": BuildLockdownView(); break;
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
            int m = 16; // margin
            int contentW = _contentArea.Width - m * 2;
            if (contentW < 200) contentW = 700; // fallback if panel not laid out yet
            int y = 10;

            // === HERO STATUS BAR ===
            var heroCard = CreateCard(new Point(m, y), new Size(contentW, 70));
            heroCard.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            heroCard.Paint += (s, e) =>
            {
                var g = e.Graphics;
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

                var hasData = _health != null && (_health.CpuPercent > 0 || _health.RamPercent > 0);
                var statusColor = hasData ? AccentGreen : AccentOrange;

                // Colored left accent bar
                using var accentBrush = new SolidBrush(statusColor);
                g.FillRectangle(accentBrush, 0, 0, 5, heroCard.Height);

                // Shield circle
                g.FillEllipse(accentBrush, 16, 13, 40, 40);
                using var checkPen = new Pen(Color.White, 2.5f) { StartCap = LineCap.Round, EndCap = LineCap.Round };
                if (hasData) { g.DrawLine(checkPen, 28, 34, 34, 40); g.DrawLine(checkPen, 34, 40, 44, 27); }
                else
                {
                    using var dotFont = new Font("Segoe UI", 14, FontStyle.Bold);
                    using var wb = new SolidBrush(Color.White);
                    g.DrawString("...", dotFont, wb, 24, 17);
                }

                // Status text
                var statusText = hasData ? "Protection Active" : "Connecting...";
                using var statusFont = new Font("Segoe UI", 15, FontStyle.Bold);
                using var statusBrush = new SolidBrush(TextDark);
                g.DrawString(statusText, statusFont, statusBrush, 64, 8);

                // Sub-info row
                using var subFont = new Font("Segoe UI", 9f);
                using var subBrush = new SolidBrush(TextMuted);
                var score = _securityResult?.TotalScore ?? 0;
                var scanTime = _securityResult?.ScanTime.ToString("MMM d, h:mm tt") ?? "Never";
                var subParts = new List<string>();
                if (hasData) subParts.Add($"Security: {score}/100");
                subParts.Add($"Scan: {scanTime}");
                if (_health != null)
                {
                    var up = _health.Uptime;
                    subParts.Add($"Uptime: {(int)up.TotalDays}d {up.Hours}h {up.Minutes}m");
                }
                g.DrawString(string.Join("   |   ", subParts), subFont, subBrush, 66, 40);
            };
            _contentArea.Controls.Add(heroCard);
            y += 78;

            // === SYSTEM GAUGES - 4 cards in a row ===
            int gap = 10;
            int gaugeW = (contentW - gap * 3) / 4;
            int gaugeH = 140;

            float cpuVal = _health?.CpuPercent ?? 0;
            float ramVal = _health?.RamPercent ?? 0;
            float diskVal = _health?.Disks.FirstOrDefault()?.UsedPercent ?? 0;
            float tempVal = _health?.CpuTempC ?? 0;
            string ramDetail = _health != null ? $"{_health.RamUsedGB:F1} / {_health.RamTotalGB:F1} GB" : "";
            var firstDisk = _health?.Disks.FirstOrDefault();
            string diskDetail = firstDisk != null ? $"{firstDisk.TotalGB - firstDisk.FreeGB:F0} / {firstDisk.TotalGB:F0} GB" : "";
            string tempDetail = tempVal > 0 ? $"{tempVal:F0}\u00B0C" : "No sensor";

            var cpuCard = CreateGaugeCard("CPU", cpuVal, "%", AccentBlue,
                new Point(m, y), new Size(gaugeW, gaugeH));
            var ramCard = CreateGaugeCard("Memory", ramVal, "%", AccentTeal,
                new Point(m + gaugeW + gap, y), new Size(gaugeW, gaugeH), ramDetail);
            var diskCard = CreateGaugeCard("Disk", diskVal, "%", AccentOrange,
                new Point(m + (gaugeW + gap) * 2, y), new Size(gaugeW, gaugeH), diskDetail);
            var tempCard = CreateGaugeCard("Temp", tempVal, "\u00B0C", AccentRed,
                new Point(m + (gaugeW + gap) * 3, y), new Size(gaugeW, gaugeH), tempDetail);

            _contentArea.Controls.Add(cpuCard);
            _contentArea.Controls.Add(ramCard);
            _contentArea.Controls.Add(diskCard);
            _contentArea.Controls.Add(tempCard);
            // Bring gauge cards to front to ensure visibility
            cpuCard.BringToFront();
            ramCard.BringToFront();
            diskCard.BringToFront();
            tempCard.BringToFront();
            y += gaugeH + 8;

            // === MIDDLE ROW: Hardware Monitor + Quick Actions ===
            int leftW = (contentW * 55) / 100;  // 55% for process monitor
            int rightW = contentW - leftW - gap;

            // Hardware Monitor (left)
            var monitorCard = CreateCard(new Point(m, y), new Size(leftW, 290));
            monitorCard.Anchor = AnchorStyles.Top | AnchorStyles.Left;
            AddHardwareMonitor(monitorCard);
            _contentArea.Controls.Add(monitorCard);

            // Quick Actions (right)
            var quickCard = CreateCard(new Point(m + leftW + gap, y), new Size(rightW, 290));
            quickCard.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            AddQuickActions(quickCard);
            _contentArea.Controls.Add(quickCard);
            y += 298;

            // === PREMIUM FEATURES BAR ===
            var premCard = CreateCard(new Point(m, y), new Size(contentW, 110));
            premCard.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            premCard.Paint += (s, e) =>
            {
                var g = e.Graphics;
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

                // Purple gradient header bar
                using var headerBrush = new SolidBrush(Color.FromArgb(140, 82, 210));
                using var headerPath = new GraphicsPath();
                headerPath.AddArc(0, 0, 16, 16, 180, 90);
                headerPath.AddArc(premCard.Width - 17, 0, 16, 16, 270, 90);
                headerPath.AddLine(premCard.Width - 1, 8, premCard.Width - 1, 28);
                headerPath.AddLine(premCard.Width - 1, 28, 0, 28);
                headerPath.AddLine(0, 28, 0, 8);
                headerPath.CloseFigure();
                g.FillPath(headerBrush, headerPath);

                using var headerFont = new Font("Segoe UI", 10, FontStyle.Bold);
                using var whiteBrush = new SolidBrush(Color.White);
                g.DrawString("Premium Features  -  Upgrade to unlock advanced protection", headerFont, whiteBrush, 12, 5);

                var features = new[]
                {
                    ("Ransomware Shield", "File protection & rollback"),
                    ("AI Threat Analysis", "Behavioral detection"),
                    ("Remote Lockdown", "Lock device remotely"),
                    ("Backup & Recovery", "Cloud backup & restore")
                };

                int fx = 10;
                int fCardW = (premCard.Width - 50) / 4;
                using var fBg = new SolidBrush(Color.FromArgb(245, 243, 252));
                using var fBorder = new Pen(Color.FromArgb(210, 200, 230));
                using var fNameFont = new Font("Segoe UI", 9f, FontStyle.Bold);
                using var fDescFont = new Font("Segoe UI", 7.5f);
                using var fGray = new SolidBrush(Color.FromArgb(140, 130, 160));

                for (int i = 0; i < features.Length; i++)
                {
                    var (name, desc) = features[i];
                    var fRect = new Rectangle(fx + i * (fCardW + 10), 36, fCardW, 64);
                    using var fPath = RoundedRect(fRect, 6);
                    g.FillPath(fBg, fPath);
                    g.DrawPath(fBorder, fPath);
                    g.DrawString(name, fNameFont, fGray, fRect.X + 8, fRect.Y + 8);
                    g.DrawString(desc, fDescFont, fGray, new RectangleF(fRect.X + 8, fRect.Y + 28, fRect.Width - 16, 30));
                }
            };
            _contentArea.Controls.Add(premCard);
        }

        private Panel CreateGaugeCard(string label, float value, string unit, Color color, Point loc, Size size, string? detail = null)
        {
            var card = CreateCard(loc, size);
            card.Paint += (s, e) =>
            {
                var g = e.Graphics;
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

                // Colored top accent
                using var topBrush = new SolidBrush(Color.FromArgb(40, color));
                g.FillRectangle(topBrush, 1, 1, card.Width - 2, 4);
                using var topLine = new SolidBrush(color);
                g.FillRectangle(topLine, 1, 1, card.Width - 2, 3);

                // Label at top
                using var labelFont = new Font("Segoe UI", 10f, FontStyle.Bold);
                using var labelBrush = new SolidBrush(TextDark);
                g.DrawString(label, labelFont, labelBrush, 12, 14);

                // Donut ring
                int donutSize = 72;
                int thickness = 8;
                int donutX = (card.Width - donutSize) / 2;
                int donutY = 36;
                var donutRect = new Rectangle(donutX, donutY, donutSize, donutSize);

                // Track
                using var trackPen = new Pen(Color.FromArgb(215, 220, 228), thickness);
                trackPen.StartCap = LineCap.Round; trackPen.EndCap = LineCap.Round;
                g.DrawArc(trackPen, donutRect, 0, 360);

                // Value arc
                float pct = Math.Min(value / 100f, 1f);
                float sweep = pct * 360f;
                if (sweep > 0.5f)
                {
                    var arcColor = pct > 0.9f ? AccentRed : pct > 0.75f ? AccentOrange : color;
                    using var valuePen = new Pen(arcColor, thickness);
                    valuePen.StartCap = LineCap.Round; valuePen.EndCap = LineCap.Round;
                    g.DrawArc(valuePen, donutRect, -90, sweep);
                }

                // Center value
                var displayVal = value > 0 ? $"{value:F0}" : "--";
                using var valFont = new Font("Segoe UI", 20, FontStyle.Bold);
                using var valBrush = new SolidBrush(TextDark);
                var valSize = g.MeasureString(displayVal, valFont);
                g.DrawString(displayVal, valFont, valBrush,
                    donutX + (donutSize - valSize.Width) / 2,
                    donutY + (donutSize - valSize.Height) / 2 - 2);

                // Unit below number
                using var unitFont = new Font("Segoe UI", 8f);
                using var unitBrush = new SolidBrush(TextMuted);
                var unitSize = g.MeasureString(unit, unitFont);
                g.DrawString(unit, unitFont, unitBrush,
                    donutX + (donutSize - unitSize.Width) / 2,
                    donutY + donutSize / 2 + valSize.Height / 2 - 6);

                // Detail text below donut
                if (!string.IsNullOrEmpty(detail))
                {
                    using var detFont = new Font("Segoe UI", 8.5f);
                    var detSize = g.MeasureString(detail, detFont);
                    g.DrawString(detail, detFont, unitBrush, (card.Width - detSize.Width) / 2, donutRect.Bottom + 6);
                }
            };
            return card;
        }

        private void AddHardwareMonitor(Panel card)
        {
            card.Paint += (s, e) =>
            {
                var g = e.Graphics;
                g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

                // Title with icon
                using var titleFont = new Font("Segoe UI", 11, FontStyle.Bold);
                using var titleBrush = new SolidBrush(TextDark);
                g.DrawString("Hardware Monitor", titleFont, titleBrush, 14, 10);

                // Subtitle
                using var subFont = new Font("Segoe UI", 8f);
                using var subBrush = new SolidBrush(TextMuted);
                var procCount = _health?.ProcessCount ?? 0;
                g.DrawString($"{procCount} processes running", subFont, subBrush, 14, 30);

                if (_health?.TopProcesses == null || _health.TopProcesses.Count == 0)
                {
                    using var emptyFont = new Font("Segoe UI", 9);
                    g.DrawString("Waiting for process data...", emptyFont, subBrush, 14, 56);
                    return;
                }

                // Column headers
                using var headerFont = new Font("Segoe UI", 8, FontStyle.Bold);
                using var headerBrush = new SolidBrush(Color.FromArgb(80, 90, 100));
                int hdrY = 48;
                g.DrawString("PROCESS", headerFont, headerBrush, 14, hdrY);
                g.DrawString("CPU", headerFont, headerBrush, card.Width - 148, hdrY);
                g.DrawString("RAM", headerFont, headerBrush, card.Width - 80, hdrY);

                using var linePen = new Pen(Color.FromArgb(230, 233, 237));
                g.DrawLine(linePen, 14, hdrY + 17, card.Width - 14, hdrY + 17);

                // Process rows with alternating background
                using var monoFont = new Font("Cascadia Mono", 8.5f);
                if (monoFont.Name != "Cascadia Mono")
                {
                    // Fallback if Cascadia Mono not available
                }
                using var altBg = new SolidBrush(Color.FromArgb(248, 250, 252));
                int rowY = hdrY + 22;
                int rowH = 22;

                foreach (var (proc, idx) in _health.TopProcesses.Take(7).Select((p, i) => (p, i)))
                {
                    // Alternating row background
                    if (idx % 2 == 0)
                        g.FillRectangle(altBg, 4, rowY - 1, card.Width - 8, rowH);

                    var cpuColor = proc.CpuPercent > 50 ? AccentRed :
                                   proc.CpuPercent > 20 ? AccentOrange : TextDark;
                    using var nameBrush = new SolidBrush(TextDark);
                    using var cpuBrush = new SolidBrush(cpuColor);
                    using var memBrush = new SolidBrush(TextMuted);

                    var name = proc.Name.Length > 20 ? proc.Name[..20] + ".." : proc.Name;
                    g.DrawString(name, monoFont, nameBrush, 14, rowY);
                    g.DrawString($"{proc.CpuPercent:F1}%", monoFont, cpuBrush, card.Width - 148, rowY);
                    g.DrawString($"{proc.MemoryMB:F0} MB", monoFont, memBrush, card.Width - 80, rowY);
                    rowY += rowH;
                }
            };
        }



        private void AddQuickActions(Panel card)
        {
            var titleLabel = new Label
            {
                Text = "Quick Actions", Font = new Font("Segoe UI", 11, FontStyle.Bold),
                ForeColor = TextDark, BackColor = Color.Transparent,
                Location = new Point(14, 10), AutoSize = true
            };
            card.Controls.Add(titleLabel);

            var actions = new (string text, string desc, Color color, Func<Task> action)[]
            {
                ("Security Scan", "Scan for vulnerabilities", AccentTeal, async () =>
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
                ("Fix My Computer", "Clear temp, flush DNS, reset network", AccentBlue, async () =>
                {
                    var confirm = MessageBox.Show(
                        "This will:\n- Clear temporary & thumbnail caches\n- Flush DNS & ARP caches\n" +
                        "- Reset Winsock & TCP/IP stack\n- Run System File Checker & DISM repair\n" +
                        "- Reset Windows Store cache\n- Refresh icons & restart Explorer\n\nContinue?",
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
                ("Speed Test", "Test internet connection speed", AccentOrange, async () =>
                {
                    await RunSpeedTestAsync();
                }),
                ("Report Card", "Generate security report for this PC", Color.FromArgb(128, 90, 213), async () =>
                {
                    await GenerateReportCardAsync();
                }),
                ("Take Screenshot", "Save screenshot to Pictures", AccentGreen, async () =>
                {
                    await Task.CompletedTask;
                    TakeScreenshot();
                })
            };

            int btnY = 38;
            int btnH = 44;
            int btnGap = 6;
            foreach (var (text, desc, color, action) in actions)
            {
                var btn = new Panel
                {
                    Location = new Point(10, btnY), Size = new Size(card.Width - 20, btnH),
                    BackColor = Color.FromArgb(248, 249, 250), Cursor = Cursors.Hand
                };
                btn.Paint += (s, e) =>
                {
                    var g = e.Graphics;
                    g.SmoothingMode = SmoothingMode.AntiAlias;
                    g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

                    using var borderPen = new Pen(CardBorder);
                    using var path = RoundedRect(new Rectangle(0, 0, btn.Width - 1, btn.Height - 1), 6);
                    g.DrawPath(borderPen, path);

                    // Color bar on left
                    using var barBrush = new SolidBrush(color);
                    g.FillRectangle(barBrush, 0, 6, 4, btn.Height - 12);

                    using var nameFont = new Font("Segoe UI", 9.5f, FontStyle.Bold);
                    using var descFont = new Font("Segoe UI", 7.5f);
                    using var nameBrush = new SolidBrush(TextDark);
                    using var descBrush = new SolidBrush(TextMuted);
                    g.DrawString(text, nameFont, nameBrush, 14, 4);
                    g.DrawString(desc, descFont, descBrush, 14, 23);

                    using var arrowFont = new Font("Segoe UI", 11);
                    g.DrawString("\u203A", arrowFont, descBrush, btn.Width - 20, 10);
                };
                btn.MouseEnter += (s, e) => btn.BackColor = Color.FromArgb(235, 240, 248);
                btn.MouseLeave += (s, e) => btn.BackColor = Color.FromArgb(248, 249, 250);
                btn.Click += async (s, e) =>
                {
                    try { await action(); }
                    catch { }
                };
                card.Controls.Add(btn);
                btnY += btnH + btnGap;
            }
        }

        private async Task RunSpeedTestAsync()
        {
            var form = new Form
            {
                Text = "Internet Speed Test", Size = new Size(460, 380),
                StartPosition = FormStartPosition.CenterParent,
                FormBorderStyle = FormBorderStyle.FixedDialog,
                MaximizeBox = false, MinimizeBox = false, BackColor = Color.White
            };

            // Custom painted gauge panel
            double pingMs = 0, downloadMbps = 0, uploadMbps = 0;
            string phase = "Testing ping...";
            bool done = false;

            var gaugePanel = new Panel { Dock = DockStyle.Fill };
            gaugePanel.Paint += (s, e) =>
            {
                var g = e.Graphics;
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

                // Title
                using var titleFont = new Font("Segoe UI", 14, FontStyle.Bold);
                using var titleBrush = new SolidBrush(TextDark);
                g.DrawString("Internet Speed Test", titleFont, titleBrush, 20, 12);

                // Gauge arc background
                int gaugeX = (form.ClientSize.Width - 200) / 2;
                int gaugeY = 50;
                var gaugeRect = new Rectangle(gaugeX, gaugeY, 200, 200);

                using var trackPen = new Pen(Color.FromArgb(230, 235, 240), 14);
                trackPen.StartCap = LineCap.Round; trackPen.EndCap = LineCap.Round;
                g.DrawArc(trackPen, gaugeRect, 180, 180);

                // Gauge value arc (download speed, max ~500 Mbps)
                double currentSpeed = done ? downloadMbps : (phase.Contains("download") ? downloadMbps : 0);
                float speedPct = (float)Math.Min(currentSpeed / 500.0, 1.0);
                float speedSweep = speedPct * 180f;
                if (speedSweep > 0.5f)
                {
                    var arcColor = currentSpeed > 100 ? AccentGreen :
                                   currentSpeed > 50 ? AccentBlue :
                                   currentSpeed > 20 ? AccentOrange : AccentRed;
                    using var speedPen = new Pen(arcColor, 14);
                    speedPen.StartCap = LineCap.Round; speedPen.EndCap = LineCap.Round;
                    g.DrawArc(speedPen, gaugeRect, 180, speedSweep);
                }

                // Center speed value
                var speedStr = done ? $"{downloadMbps:F1}" : (downloadMbps > 0 ? $"{downloadMbps:F1}" : "--");
                using var speedFont = new Font("Segoe UI", 32, FontStyle.Bold);
                using var speedBrush = new SolidBrush(TextDark);
                var speedSize = g.MeasureString(speedStr, speedFont);
                g.DrawString(speedStr, speedFont, speedBrush,
                    gaugeX + (200 - speedSize.Width) / 2, gaugeY + 55);

                using var unitFont = new Font("Segoe UI", 11);
                using var unitBrush = new SolidBrush(TextMuted);
                var mbStr = "Mb/s";
                var mbSize = g.MeasureString(mbStr, unitFont);
                g.DrawString(mbStr, unitFont, unitBrush,
                    gaugeX + (200 - mbSize.Width) / 2, gaugeY + 100);

                // Scale labels on the arc
                using var scaleFont = new Font("Segoe UI", 7);
                g.DrawString("0", scaleFont, unitBrush, gaugeX - 5, gaugeY + 200);
                g.DrawString("250", scaleFont, unitBrush, gaugeX + 90, gaugeY - 10);
                g.DrawString("500", scaleFont, unitBrush, gaugeX + 195, gaugeY + 200);

                // Status text
                using var statusFont = new Font("Segoe UI", 10);
                var statusStr = done ? "Test Complete" : phase;
                var statusColor = done ? AccentGreen : AccentBlue;
                using var statusBrush = new SolidBrush(statusColor);
                var statusSize = g.MeasureString(statusStr, statusFont);
                g.DrawString(statusStr, statusFont, statusBrush,
                    (form.ClientSize.Width - statusSize.Width) / 2, gaugeY + 160);

                // Bottom stats: Ping | Download | Upload
                int statsY = gaugeY + 210;
                int colW = form.ClientSize.Width / 3;

                using var labelFont = new Font("Segoe UI", 9, FontStyle.Bold);
                using var valueFont = new Font("Segoe UI", 16, FontStyle.Bold);
                using var labelBrush2 = new SolidBrush(TextMuted);

                // Ping
                var pingStr = pingMs > 0 ? $"{pingMs:F0}" : "--";
                var pingValSize = g.MeasureString(pingStr, valueFont);
                g.DrawString(pingStr, valueFont, titleBrush, (colW - pingValSize.Width) / 2, statsY);
                var pingLabel = "Ping (ms)";
                var pingLabelSize = g.MeasureString(pingLabel, labelFont);
                g.DrawString(pingLabel, labelFont, labelBrush2, (colW - pingLabelSize.Width) / 2, statsY + 30);

                // Download
                var dlStr = downloadMbps > 0 ? $"{downloadMbps:F1}" : "--";
                var dlValSize = g.MeasureString(dlStr, valueFont);
                g.DrawString(dlStr, valueFont, titleBrush, colW + (colW - dlValSize.Width) / 2, statsY);
                var dlLabel = "Download (Mb/s)";
                var dlLabelSize = g.MeasureString(dlLabel, labelFont);
                g.DrawString(dlLabel, labelFont, labelBrush2, colW + (colW - dlLabelSize.Width) / 2, statsY + 30);

                // Upload
                var ulStr = uploadMbps > 0 ? $"{uploadMbps:F1}" : "--";
                var ulValSize = g.MeasureString(ulStr, valueFont);
                g.DrawString(ulStr, valueFont, titleBrush, colW * 2 + (colW - ulValSize.Width) / 2, statsY);
                var ulLabel = "Upload (Mb/s)";
                var ulLabelSize = g.MeasureString(ulLabel, labelFont);
                g.DrawString(ulLabel, labelFont, labelBrush2, colW * 2 + (colW - ulLabelSize.Width) / 2, statsY + 30);
            };
            form.Controls.Add(gaugePanel);
            form.Show(this);

            try
            {
                using var http = new System.Net.Http.HttpClient { Timeout = TimeSpan.FromSeconds(60) };
                http.DefaultRequestHeaders.UserAgent.ParseAdd("PCPlus/4.11 SpeedTest");

                // Ping test - average of 5 pings
                phase = "Testing ping...";
                gaugePanel.Invalidate();
                try
                {
                    using var ping = new System.Net.NetworkInformation.Ping();
                    var pings = new List<long>();
                    for (int i = 0; i < 5; i++)
                    {
                        var reply = await ping.SendPingAsync("8.8.8.8", 3000);
                        if (reply.Status == System.Net.NetworkInformation.IPStatus.Success)
                            pings.Add(reply.RoundtripTime);
                        await Task.Delay(100);
                    }
                    if (pings.Count > 0)
                        pingMs = pings.OrderBy(p => p).Take(3).Average(); // best 3 of 5
                }
                catch { pingMs = 0; }
                gaugePanel.Invalidate();

                // Download test - streaming with live speed updates
                phase = "Testing download...";
                gaugePanel.Invalidate();
                var dlUrls = new[]
                {
                    "http://speedtest.tele2.net/100MB.zip",
                    "http://proof.ovh.net/files/100Mb.dat",
                    "http://speedtest.tele2.net/10MB.zip"
                };
                foreach (var url in dlUrls)
                {
                    try
                    {
                        using var response = await http.GetAsync(url, System.Net.Http.HttpCompletionOption.ResponseHeadersRead);
                        response.EnsureSuccessStatusCode();
                        using var stream = await response.Content.ReadAsStreamAsync();
                        var buffer = new byte[65536];
                        long totalBytes = 0;
                        var sw = System.Diagnostics.Stopwatch.StartNew();
                        var lastUpdate = sw.ElapsedMilliseconds;
                        int bytesRead;
                        // Download for at least 8 seconds or until stream ends
                        while ((bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length)) > 0)
                        {
                            totalBytes += bytesRead;
                            var elapsed = sw.ElapsedMilliseconds;
                            if (elapsed - lastUpdate > 500) // update gauge every 500ms
                            {
                                downloadMbps = (totalBytes * 8.0) / (elapsed / 1000.0) / 1_000_000.0;
                                lastUpdate = elapsed;
                                form.BeginInvoke(new Action(() => gaugePanel.Invalidate()));
                            }
                            if (elapsed > 12000) break; // cap at 12 seconds
                        }
                        sw.Stop();
                        if (sw.Elapsed.TotalSeconds > 0.5)
                            downloadMbps = (totalBytes * 8.0) / sw.Elapsed.TotalSeconds / 1_000_000.0;
                        form.BeginInvoke(new Action(() => gaugePanel.Invalidate()));
                        break;
                    }
                    catch { continue; }
                }

                // Upload test - 10MB with streaming measurement
                phase = "Testing upload...";
                form.BeginInvoke(new Action(() => gaugePanel.Invalidate()));
                try
                {
                    var uploadSize = 10 * 1024 * 1024; // 10MB
                    var uploadData = new byte[uploadSize];
                    new Random().NextBytes(uploadData);
                    var sw = System.Diagnostics.Stopwatch.StartNew();
                    using var content = new System.Net.Http.ByteArrayContent(uploadData);
                    content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");
                    await http.PostAsync("http://speedtest.tele2.net/upload.php", content);
                    sw.Stop();
                    if (sw.Elapsed.TotalSeconds > 0.1)
                        uploadMbps = (uploadData.Length * 8.0) / sw.Elapsed.TotalSeconds / 1_000_000.0;
                }
                catch { uploadMbps = 0; }

                done = true;
                phase = "Test Complete";
                form.BeginInvoke(new Action(() => gaugePanel.Invalidate()));
            }
            catch
            {
                phase = "Test Failed";
                form.BeginInvoke(new Action(() => gaugePanel.Invalidate()));
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
                var alertCard = CreateCard(new Point(24, y), new Size(_contentArea.Width - 72, 72));
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

                    // Dim card if acknowledged
                    if (localAlert.Acknowledged)
                    {
                        using var dimBrush = new SolidBrush(Color.FromArgb(245, 245, 245));
                        g.FillRectangle(dimBrush, 0, 0, alertCard.Width, alertCard.Height);
                    }

                    // Severity bar on left
                    using var barBrush = new SolidBrush(localAlert.Acknowledged ? TextMuted : sevColor);
                    g.FillRectangle(barBrush, 0, 0, 4, alertCard.Height);

                    // Title
                    using var titleFont = new Font("Segoe UI", 10, FontStyle.Bold);
                    using var titleBrush = new SolidBrush(localAlert.Acknowledged ? TextMuted : TextDark);
                    g.DrawString(localAlert.Title, titleFont, titleBrush, 16, 8);

                    // Message
                    using var msgFont = new Font("Segoe UI", 8.5f);
                    using var msgBrush = new SolidBrush(TextMuted);
                    var msg = localAlert.Message.Length > 80 ? localAlert.Message[..80] + "..." : localAlert.Message;
                    g.DrawString(msg, msgFont, msgBrush, 16, 30);

                    // Timestamp
                    using var timeFont = new Font("Segoe UI", 7.5f);
                    var timeStr = localAlert.Timestamp.ToString("MMM d, h:mm tt");
                    var timeSize = g.MeasureString(timeStr, timeFont);
                    g.DrawString(timeStr, timeFont, msgBrush, alertCard.Width - timeSize.Width - 16, 10);

                    // Dismiss / Dismissed badge
                    if (localAlert.Acknowledged)
                    {
                        using var ackFont = new Font("Segoe UI", 7.5f, FontStyle.Italic);
                        using var ackBrush = new SolidBrush(AccentGreen);
                        g.DrawString("\u2713 Dismissed", ackFont, ackBrush, alertCard.Width - 90, 50);
                    }
                    else
                    {
                        // Draw dismiss button area
                        var btnRect = new Rectangle(alertCard.Width - 90, 46, 74, 20);
                        using var btnBrush = new SolidBrush(Color.FromArgb(230, 230, 230));
                        using var btnPen = new Pen(Color.FromArgb(200, 200, 200));
                        g.FillRectangle(btnBrush, btnRect);
                        g.DrawRectangle(btnPen, btnRect);
                        using var btnFont = new Font("Segoe UI", 7.5f);
                        using var btnTextBrush = new SolidBrush(TextDark);
                        var btnText = "Dismiss";
                        var btnTextSize = g.MeasureString(btnText, btnFont);
                        g.DrawString(btnText, btnFont, btnTextBrush,
                            btnRect.X + (btnRect.Width - btnTextSize.Width) / 2,
                            btnRect.Y + (btnRect.Height - btnTextSize.Height) / 2);
                    }
                };

                // Click handler for dismiss button
                if (!localAlert.Acknowledged)
                {
                    var capturedAlert = localAlert;
                    alertCard.MouseClick += async (s, e) =>
                    {
                        // Check if click is in the dismiss button area
                        var btnRect = new Rectangle(alertCard.Width - 90, 46, 74, 20);
                        if (btnRect.Contains(e.Location))
                        {
                            try
                            {
                                if (_ipc.IsConnected && !_usingLocalFallback)
                                    await Task.Run(() => _ipc.AcknowledgeAlertAsync(capturedAlert.Id));
                                capturedAlert.Acknowledged = true;
                                alertCard.Invalidate();
                            }
                            catch { /* Silently fail - next refresh will sync */ }
                        }
                    };
                    // Cursor change on hover over dismiss button
                    alertCard.MouseMove += (s, e) =>
                    {
                        var btnRect = new Rectangle(alertCard.Width - 90, 46, 74, 20);
                        alertCard.Cursor = btnRect.Contains(e.Location) ? Cursors.Hand : Cursors.Default;
                    };
                }

                _contentArea.Controls.Add(alertCard);
                y += 80;
            }
        }

        #endregion

        #region Lockdown Mode View

        private void BuildLockdownView()
        {
            var title = CreatePageTitle("Lockdown Mode");
            _contentArea.Controls.Add(title);

            int m = 16;
            int contentW = _contentArea.Width - m * 2 - 24;
            if (contentW < 200) contentW = 660;
            int y = 55;

            // Status card - shows current lockdown state
            var statusCard = CreateCard(new Point(m + 12, y), new Size(contentW, 130));
            statusCard.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;

            bool isLocked = false;
            string lockReason = "";
            string lockTime = "";

            // Try to get lockdown state from service
            if (_ipc.IsConnected && !_usingLocalFallback)
            {
                try
                {
                    var resp = _ipc.SendModuleCommandAsync("ransomware", "GetStatus",
                        new Dictionary<string, string>()).GetAwaiter().GetResult();
                    if (resp.Success && !string.IsNullOrEmpty(resp.JsonData))
                    {
                        using var doc = System.Text.Json.JsonDocument.Parse(resp.JsonData);
                        if (doc.RootElement.TryGetProperty("lockdown", out var ld))
                        {
                            isLocked = ld.TryGetProperty("IsActive", out var ia) && ia.GetBoolean();
                            if (ld.TryGetProperty("Reason", out var r)) lockReason = r.GetString() ?? "";
                            if (ld.TryGetProperty("ActivatedAt", out var at))
                                lockTime = at.GetDateTime().ToString("MMM d, h:mm tt");
                        }
                    }
                }
                catch { }
            }

            var capturedLocked = isLocked;
            var capturedReason = lockReason;
            var capturedTime = lockTime;

            statusCard.Paint += (s, e) =>
            {
                var g = e.Graphics;
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

                // Status icon
                var iconColor = capturedLocked ? AccentRed : AccentGreen;
                using var iconBrush = new SolidBrush(iconColor);
                g.FillEllipse(iconBrush, 20, 20, 40, 40);
                using var iconFont = new Font("Segoe UI", 18, FontStyle.Bold);
                using var iconTextBrush = new SolidBrush(Color.White);
                var iconChar = capturedLocked ? "\u26A0" : "\u2713";
                var iconSize = g.MeasureString(iconChar, iconFont);
                g.DrawString(iconChar, iconFont, iconTextBrush,
                    20 + (40 - iconSize.Width) / 2, 20 + (40 - iconSize.Height) / 2);

                // Status text
                using var statusFont = new Font("Segoe UI", 16, FontStyle.Bold);
                using var statusBrush = new SolidBrush(capturedLocked ? AccentRed : AccentGreen);
                g.DrawString(capturedLocked ? "LOCKDOWN ACTIVE" : "System Normal",
                    statusFont, statusBrush, 75, 18);

                using var detailFont = new Font("Segoe UI", 9.5f);
                using var detailBrush = new SolidBrush(TextMuted);
                if (capturedLocked)
                {
                    g.DrawString($"Activated: {capturedTime}", detailFont, detailBrush, 75, 50);
                    var reasonStr = capturedReason.Length > 70 ? capturedReason[..70] + "..." : capturedReason;
                    g.DrawString($"Reason: {reasonStr}", detailFont, detailBrush, 75, 70);
                }
                else
                {
                    g.DrawString("No active threats. Lockdown will activate automatically if a severe threat is detected.",
                        detailFont, detailBrush, 75, 50);
                    g.DrawString("You can also activate lockdown manually using the button below.",
                        detailFont, detailBrush, 75, 70);
                }
            };
            _contentArea.Controls.Add(statusCard);
            y += 142;

            // Action button - toggle lockdown
            var btnCard = CreateCard(new Point(m + 12, y), new Size(contentW, 55));
            btnCard.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            btnCard.Cursor = Cursors.Hand;
            var btnLocked = capturedLocked;
            btnCard.Paint += (s, e) =>
            {
                var g = e.Graphics;
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

                var bgColor = btnLocked ? AccentGreen : AccentRed;
                using var bgBrush = new SolidBrush(bgColor);
                var rect = new Rectangle(20, 10, btnCard.Width - 40, 35);
                using var path = new GraphicsPath();
                int r = 6;
                path.AddArc(rect.X, rect.Y, r * 2, r * 2, 180, 90);
                path.AddArc(rect.Right - r * 2, rect.Y, r * 2, r * 2, 270, 90);
                path.AddArc(rect.Right - r * 2, rect.Bottom - r * 2, r * 2, r * 2, 0, 90);
                path.AddArc(rect.X, rect.Bottom - r * 2, r * 2, r * 2, 90, 90);
                path.CloseFigure();
                g.FillPath(bgBrush, path);

                using var btnFont = new Font("Segoe UI", 11, FontStyle.Bold);
                using var btnBrush = new SolidBrush(Color.White);
                var text = btnLocked ? "\u2713 Deactivate Lockdown" : "\u26A0 Activate Lockdown Now";
                var textSize = g.MeasureString(text, btnFont);
                g.DrawString(text, btnFont, btnBrush,
                    rect.X + (rect.Width - textSize.Width) / 2,
                    rect.Y + (rect.Height - textSize.Height) / 2);
            };
            btnCard.Click += async (s, e) =>
            {
                if (!_ipc.IsConnected || _usingLocalFallback)
                {
                    MessageBox.Show("Service not connected. Lockdown requires the PC Plus service.",
                        "PC Plus", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                var action = btnLocked ? "DeactivateLockdown" : "ActivateLockdown";
                var confirmMsg = btnLocked
                    ? "Deactivate lockdown? This will restore network and RDP access."
                    : "Activate lockdown? This will:\n\n- Kill all suspicious processes\n- Disable network (if auto-containment enabled)\n- Disable Remote Desktop\n\nOnly do this if you suspect an active threat.";

                if (MessageBox.Show(confirmMsg, "PC Plus Lockdown",
                    MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes)
                    return;

                try
                {
                    await Task.Run(() => _ipc.SendModuleCommandAsync("ransomware", action,
                        new Dictionary<string, string>()));
                    btnLocked = !btnLocked;
                    ShowView("lockdown"); // Refresh entire view
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Failed: {ex.Message}", "PC Plus", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            };
            _contentArea.Controls.Add(btnCard);
            y += 67;

            // Info card - what lockdown does
            var infoCard = CreateCard(new Point(m + 12, y), new Size(contentW, 180));
            infoCard.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            infoCard.Paint += (s, e) =>
            {
                var g = e.Graphics;
                g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

                using var headerFont = new Font("Segoe UI", 11, FontStyle.Bold);
                using var headerBrush = new SolidBrush(TextDark);
                g.DrawString("What does Lockdown Mode do?", headerFont, headerBrush, 20, 14);

                using var itemFont = new Font("Segoe UI", 9.5f);
                using var itemBrush = new SolidBrush(TextMuted);
                using var bulletBrush = new SolidBrush(AccentTeal);

                var items = new[]
                {
                    "Immediately kills all processes flagged by the behavior scoring engine",
                    "Disables network adapters to prevent data exfiltration (if auto-containment enabled)",
                    "Disables Remote Desktop to block remote access by attackers",
                    "Sends an Emergency alert to the dashboard and all notification channels",
                    "Remains active until manually deactivated by an administrator"
                };

                int iy = 42;
                foreach (var item in items)
                {
                    g.FillEllipse(bulletBrush, 24, iy + 5, 6, 6);
                    g.DrawString(item, itemFont, itemBrush, 40, iy);
                    iy += 26;
                }
            };
            _contentArea.Controls.Add(infoCard);
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

        private async Task GenerateReportCardAsync()
        {
            await Task.CompletedTask;

            var reportDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                "PC Plus Reports");
            Directory.CreateDirectory(reportDir);

            var hostname = Environment.MachineName;
            var reportDate = DateTime.Now;
            var filename = $"PCPlus_Report_{hostname}_{reportDate:yyyy-MM-dd}.html";
            var filepath = Path.Combine(reportDir, filename);

            // Gather data
            var secScore = _securityResult?.TotalScore ?? 0;
            var secGrade = _securityResult?.Grade ?? "?";
            var checks = _securityResult?.Checks ?? new List<PCPlus.Core.Models.SecurityCheck>();
            var passedCount = checks.Count(c => c.Passed);
            var failedCount = checks.Count(c => !c.Passed);
            var totalChecks = checks.Count;

            var cpu = _health?.CpuPercent ?? 0;
            var ram = _health?.RamPercent ?? 0;
            var ramUsed = _health?.RamUsedGB ?? 0;
            var ramTotal = _health?.RamTotalGB ?? 0;
            var cpuTemp = _health?.CpuTempC ?? 0;
            var gpuTemp = _health?.GpuTempC ?? 0;
            var uptime = _health?.Uptime ?? TimeSpan.Zero;
            var osVersion = GetFriendlyOsVersion();

            var gradeColor = secGrade switch
            {
                "A" => "#2eb85c",
                "B" => "#39f",
                "C" => "#f5a623",
                "D" => "#e55",
                "F" => "#dc3545",
                _ => "#888"
            };

            // Build category summary for security checks
            var categories = checks.GroupBy(c => c.Category)
                .Select(g => new
                {
                    Name = g.Key,
                    Total = g.Count(),
                    Passed = g.Count(c => c.Passed),
                    Failed = g.Count(c => !c.Passed)
                }).OrderByDescending(c => c.Failed).ToList();

            // Build failed checks HTML
            var failedChecksHtml = "";
            foreach (var check in checks.Where(c => !c.Passed).OrderBy(c => c.Category))
            {
                failedChecksHtml += $@"
                <tr>
                    <td style='padding:8px 12px;border-bottom:1px solid #eee;'>{System.Net.WebUtility.HtmlEncode(check.Category)}</td>
                    <td style='padding:8px 12px;border-bottom:1px solid #eee;'>{System.Net.WebUtility.HtmlEncode(check.Name)}</td>
                    <td style='padding:8px 12px;border-bottom:1px solid #eee;color:#888;'>{System.Net.WebUtility.HtmlEncode(check.Recommendation)}</td>
                </tr>";
            }

            // Build disk info
            var diskHtml = "";
            if (_health?.Disks != null)
            {
                foreach (var disk in _health.Disks)
                {
                    var diskColor = disk.UsedPercent > 90 ? "#dc3545" : disk.UsedPercent > 75 ? "#f5a623" : "#2eb85c";
                    diskHtml += $@"
                    <div style='margin-bottom:8px;'>
                        <div style='display:flex;justify-content:space-between;margin-bottom:4px;'>
                            <span>{System.Net.WebUtility.HtmlEncode(disk.Name)} {System.Net.WebUtility.HtmlEncode(disk.Label)}</span>
                            <span>{disk.FreeGB:F1} GB free of {disk.TotalGB:F1} GB</span>
                        </div>
                        <div style='background:#eee;border-radius:4px;height:8px;'>
                            <div style='background:{diskColor};border-radius:4px;height:8px;width:{disk.UsedPercent:F0}%;'></div>
                        </div>
                    </div>";
                }
            }

            // Active alerts summary
            var alertsSummary = $"{_alerts.Count(a => !a.Acknowledged)} unacknowledged alerts";
            var criticalAlerts = _alerts.Count(a => a.Severity >= PCPlus.Core.Models.AlertSeverity.Critical && !a.Acknowledged);

            var html = $@"<!DOCTYPE html>
<html>
<head>
<meta charset='utf-8'>
<title>PC Plus Security Report - {System.Net.WebUtility.HtmlEncode(hostname)}</title>
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; margin:0; padding:0; background:#f5f6fa; color:#333; }}
  .container {{ max-width:800px; margin:0 auto; padding:20px; }}
  .header {{ background:linear-gradient(135deg, #0078d7, #00a1f1); color:white; padding:30px; border-radius:12px 12px 0 0; }}
  .header h1 {{ margin:0; font-size:24px; }}
  .header p {{ margin:6px 0 0; opacity:0.9; }}
  .body {{ background:white; padding:30px; border-radius:0 0 12px 12px; box-shadow:0 2px 12px rgba(0,0,0,0.08); }}
  .grade-circle {{ width:100px; height:100px; border-radius:50%; display:inline-flex; align-items:center; justify-content:center; font-size:48px; font-weight:bold; color:white; float:right; margin-top:-10px; }}
  .section {{ margin-top:28px; }}
  .section h2 {{ font-size:16px; color:#0078d7; border-bottom:2px solid #0078d7; padding-bottom:6px; margin-bottom:14px; }}
  .metric-grid {{ display:grid; grid-template-columns:1fr 1fr 1fr 1fr; gap:14px; }}
  .metric {{ background:#f8f9fa; border-radius:8px; padding:14px; text-align:center; }}
  .metric .value {{ font-size:24px; font-weight:bold; }}
  .metric .label {{ font-size:11px; color:#888; margin-top:4px; }}
  table {{ width:100%; border-collapse:collapse; }}
  th {{ text-align:left; padding:8px 12px; background:#f8f9fa; border-bottom:2px solid #ddd; font-size:12px; text-transform:uppercase; color:#666; }}
  .cat-bar {{ display:inline-block; height:6px; border-radius:3px; }}
  .footer {{ text-align:center; margin-top:20px; color:#999; font-size:11px; }}
</style>
</head>
<body>
<div class='container'>
  <div class='header'>
    <div class='grade-circle' style='background:{gradeColor};'>{secGrade}</div>
    <h1>PC Plus Endpoint Security Report</h1>
    <p>{System.Net.WebUtility.HtmlEncode(hostname)} &mdash; {reportDate:MMMM d, yyyy h:mm tt}</p>
  </div>
  <div class='body'>
    <div class='section'>
      <h2>Security Score: {secScore}/100</h2>
      <div style='background:#eee;border-radius:6px;height:14px;margin-bottom:12px;'>
        <div style='background:{gradeColor};border-radius:6px;height:14px;width:{secScore}%;'></div>
      </div>
      <p>{passedCount} of {totalChecks} security checks passed. {failedCount} issues need attention.</p>
    </div>

    <div class='section'>
      <h2>System Health</h2>
      <div class='metric-grid'>
        <div class='metric'>
          <div class='value' style='color:{(cpu > 85 ? "#dc3545" : cpu > 60 ? "#f5a623" : "#2eb85c")};'>{cpu:F0}%</div>
          <div class='label'>CPU Usage</div>
        </div>
        <div class='metric'>
          <div class='value' style='color:{(ram > 85 ? "#dc3545" : ram > 60 ? "#f5a623" : "#2eb85c")};'>{ram:F0}%</div>
          <div class='label'>RAM ({ramUsed:F1}/{ramTotal:F1} GB)</div>
        </div>
        <div class='metric'>
          <div class='value'>{cpuTemp:F0}&deg;C</div>
          <div class='label'>CPU Temperature</div>
        </div>
        <div class='metric'>
          <div class='value'>{(int)uptime.TotalHours}h</div>
          <div class='label'>Uptime</div>
        </div>
      </div>
    </div>

    <div class='section'>
      <h2>Storage</h2>
      {diskHtml}
    </div>

    <div class='section'>
      <h2>Security by Category</h2>
      <table>
        <tr><th>Category</th><th>Passed</th><th>Failed</th><th>Score</th></tr>
        {string.Join("", categories.Select(c =>
        {
            var pct = c.Total > 0 ? (int)(c.Passed * 100.0 / c.Total) : 0;
            var barColor = pct >= 80 ? "#2eb85c" : pct >= 50 ? "#f5a623" : "#dc3545";
            return $@"<tr>
                <td style='padding:8px 12px;border-bottom:1px solid #eee;font-weight:600;'>{System.Net.WebUtility.HtmlEncode(c.Name)}</td>
                <td style='padding:8px 12px;border-bottom:1px solid #eee;color:#2eb85c;'>{c.Passed}</td>
                <td style='padding:8px 12px;border-bottom:1px solid #eee;color:#dc3545;'>{c.Failed}</td>
                <td style='padding:8px 12px;border-bottom:1px solid #eee;'>
                    <span class='cat-bar' style='background:{barColor};width:{pct}px;'></span> {pct}%
                </td>
            </tr>";
        }))}
      </table>
    </div>

    {(failedCount > 0 ? $@"<div class='section'>
      <h2>Issues Requiring Attention ({failedCount})</h2>
      <table>
        <tr><th>Category</th><th>Check</th><th>Recommendation</th></tr>
        {failedChecksHtml}
      </table>
    </div>" : "<div class='section'><h2>All Clear!</h2><p>All security checks passed. Your system is well-protected.</p></div>")}

    <div class='section'>
      <h2>Alerts</h2>
      <p>{alertsSummary}{(criticalAlerts > 0 ? $" ({criticalAlerts} critical)" : "")}</p>
    </div>

    <div class='section' style='background:#f8f9fa;padding:16px;border-radius:8px;'>
      <strong>System:</strong> {System.Net.WebUtility.HtmlEncode(osVersion)} &bull;
      <strong>Agent:</strong> v4.13.0 &bull;
      <strong>Last Scan:</strong> {(_securityResult?.ScanTime.ToString("MMM d, h:mm tt") ?? "Never")}
    </div>
  </div>
  <div class='footer'>
    Generated by PC Plus Endpoint Protection &mdash; PC Plus Computing<br>
    {reportDate:yyyy-MM-dd HH:mm:ss} UTC
  </div>
</div>
</body>
</html>";

            await File.WriteAllTextAsync(filepath, html);

            MessageBox.Show($"Report saved to:\n{filepath}", "Report Card Generated",
                MessageBoxButtons.OK, MessageBoxIcon.Information);

            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            { FileName = filepath, UseShellExecute = true });
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
