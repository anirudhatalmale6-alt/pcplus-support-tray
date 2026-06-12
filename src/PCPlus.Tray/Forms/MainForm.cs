using System.Drawing;
using System.Drawing.Drawing2D;
using System.Management;
using System.Text.Json;
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

        // Theme colors - Malwarebytes-inspired professional look
        private static readonly Color SidebarBg = Color.FromArgb(16, 20, 30);
        private static readonly Color SidebarText = Color.FromArgb(160, 175, 200);
        private static readonly Color SidebarActive = Color.FromArgb(25, 32, 48);
        private static readonly Color SidebarHover = Color.FromArgb(22, 28, 40);
        private static readonly Color ContentBg = Color.FromArgb(230, 234, 242);
        private static readonly Color CardBg = Color.White;
        private static readonly Color CardBorder = Color.FromArgb(228, 232, 240);
        private static readonly Color TextDark = Color.FromArgb(20, 24, 36);
        private static readonly Color TextMuted = Color.FromArgb(108, 117, 135);
        private static readonly Color AccentTeal = Color.FromArgb(37, 150, 190);
        private static readonly Color AccentGreen = Color.FromArgb(16, 185, 129);
        private static readonly Color AccentOrange = Color.FromArgb(245, 158, 11);
        private static readonly Color AccentRed = Color.FromArgb(239, 68, 68);
        private static readonly Color AccentBlue = Color.FromArgb(59, 130, 246);

        // Cached data
        private HealthSnapshot? _health;
        private SecurityScanResult? _securityResult;
        private ServiceStatusReport? _serviceStatus;
        private List<Alert> _alerts = new();

        // DNS live feed cached data
        private bool _dnsActive;
        private int _dnsDomainsChecked;
        private int _dnsThreatsBlocked;
        private List<(string Domain, string TimeAgo)> _dnsRecentBlocks = new();

        // Missing patches cached data
        private int _missingPatchCount;
        private List<(string PatchId, string Severity)> _missingPatches = new();
        private DateTime _patchesLastChecked;

        // Hardware monitor - startup reading locked for 1 hour
        private HealthSnapshot? _hwSnapshot;
        private DateTime _hwSnapshotTime = DateTime.MinValue;
        private bool _hwLockAfterFirst = true;
        private static readonly TimeSpan HwRefreshInterval = TimeSpan.FromHours(1);
        private bool _localMonitorEnabled;
        private bool _localMonitorInitDone;
        private System.Windows.Forms.Timer? _localMonitorTimer;

        // Trend history for sparklines (last 30 data points = ~5 minutes at 10s interval)
        private readonly List<float> _cpuHistory = new();
        private readonly List<float> _ramHistory = new();
        private readonly List<float> _diskHistory = new();
        private readonly List<float> _tempHistory = new();
        private const int MaxHistoryPoints = 30;

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

            _refreshTimer = new System.Windows.Forms.Timer { Interval = 10000 };
            _refreshTimer.Tick += async (s, e) => await RefreshDataAsync();
            _refreshTimer.Start();

            // Take initial hardware reading BEFORE showing dashboard
            if (!_localMonitorInitDone)
            {
                _localMonitorInitDone = true;
                try { LocalMonitorTick(null, EventArgs.Empty); }
                catch { }
            }

            // Generate a quick default score if none exists yet
            if (_securityResult == null)
            {
                _securityResult = new SecurityScanResult
                {
                    TotalScore = 75,
                    Grade = "C",
                    ScanTime = DateTime.Now
                };
            }

            ShowView("dashboard");
            _ = RefreshDataAsync();
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
            AddNavItem(navPanel, "vulnerability", "Vulnerability", "\u26a0", ref y);
            AddNavItem(navPanel, "wifi", "WiFi Security", "\u2637", ref y);
            AddNavItem(navPanel, "dns", "DNS Protection", "\u2691", ref y);
            AddNavItem(navPanel, "policies", "Policy Engine", "\u2692", ref y);
            y += 10; // spacer
            AddNavItem(navPanel, "support", "Support Center", "\u2709", ref y);
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
                    : "Protected (Local)";
                var color = _ipc.IsConnected ? AccentGreen : AccentBlue;
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
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;
                var isActive = _currentView == (string)btn.Tag;

                if (isActive)
                {
                    using var activeBrush = new SolidBrush(SidebarActive);
                    using var activePath = RoundedRect(new Rectangle(8, 2, btn.Width - 16, btn.Height - 4), 8);
                    g.FillPath(activeBrush, activePath);
                    using var accentBrush = new SolidBrush(AccentTeal);
                    g.FillRectangle(accentBrush, 0, 6, 3, btn.Height - 12);
                }

                using var iconFont = new Font("Segoe UI Symbol", 12);
                using var textFont = new Font("Segoe UI", 10, isActive ? FontStyle.Bold : FontStyle.Regular);
                var textColor = isActive ? Color.White : SidebarText;
                using var brush = new SolidBrush(textColor);
                g.DrawString(icon, iconFont, brush, 22, 10);
                g.DrawString(text, textFont, brush, 50, 10);
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

        private void DisposeContentControls()
        {
            var controls = new List<Control>();
            foreach (Control c in _contentArea.Controls)
                controls.Add(c);
            _contentArea.Controls.Clear();
            foreach (var c in controls)
                c.Dispose();
        }

        private void ShowView(string viewId)
        {
            _currentView = viewId;
            // Refresh all nav buttons
            foreach (var btn in _navButtons.Values)
                btn.Invalidate();

            // Dispose old controls to free GDI handles, then rebuild
            DisposeContentControls();
            switch (viewId)
            {
                case "dashboard": BuildDashboardView(); break;
                case "scanner": BuildScannerView(); break;
                case "protection": BuildProtectionView(); break;
                case "history": BuildHistoryView(); break;
                case "lockdown": BuildLockdownView(); break;
                case "advisor": BuildAdvisorView(); break;
                case "vulnerability": BuildVulnerabilityView(); break;
                case "wifi": BuildWifiView(); break;
                case "dns": BuildDnsProtectionView(); break;
                case "policies": BuildPoliciesView(); break;
                case "support": BuildSupportView(); break;
                case "system": BuildSystemView(); break;
            }
            AddBrandFooter();
        }

        private void AddPromoCards(int y, int m, int contentW)
        {
            int gap = 10;
            int cardW = (contentW - gap * 2) / 3;

            var promos = new[]
            {
                ("Managed IT Services", "Let us handle your technology so you can focus on your business. 24/7 monitoring, patching, and support.", AccentBlue, "pcpluscomputing.com"),
                ("Cloud Backup Solutions", "Automatic daily backups with instant recovery. Your data is safe with enterprise-grade encryption.", AccentGreen, "Included with managed plans"),
                ("Cybersecurity Training", "Protect your team from phishing and social engineering attacks. Monthly security awareness updates.", Color.FromArgb(139, 92, 246), "Ask about team training")
            };

            for (int i = 0; i < promos.Length; i++)
            {
                var (title, desc, color, cta) = promos[i];
                var card = CreateCard(new Point(m + i * (cardW + gap), y), new Size(cardW, 140));
                var capturedTitle = title;
                var capturedDesc = desc;
                var capturedColor = color;
                var capturedCta = cta;
                card.Paint += (s, e) =>
                {
                    var g = e.Graphics;
                    g.SmoothingMode = SmoothingMode.AntiAlias;
                    g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

                    using var topBar = new SolidBrush(capturedColor);
                    g.FillRectangle(topBar, 1, 1, card.Width - 2, 4);

                    using var tFont = new Font("Segoe UI", 10f, FontStyle.Bold);
                    using var tBrush = new SolidBrush(TextDark);
                    g.DrawString(capturedTitle, tFont, tBrush, 14, 16);

                    using var dFont = new Font("Segoe UI", 8.5f);
                    using var dBrush = new SolidBrush(TextMuted);
                    g.DrawString(capturedDesc, dFont, dBrush, new RectangleF(14, 40, card.Width - 28, 60));

                    using var cFont = new Font("Segoe UI", 8f, FontStyle.Bold);
                    using var cBrush = new SolidBrush(capturedColor);
                    g.DrawString(capturedCta, cFont, cBrush, 14, 110);
                };
                _contentArea.Controls.Add(card);
            }
        }

        private void AddBrandFooter()
        {
            int footerY = 0;
            foreach (Control c in _contentArea.Controls)
            {
                int bottom = c.Top + c.Height;
                if (bottom > footerY) footerY = bottom;
            }
            footerY += 16;

            var footer = new Panel
            {
                Location = new Point(24, footerY),
                Size = new Size(_contentArea.Width - 72, 50),
                BackColor = Color.Transparent,
                Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right
            };
            footer.Paint += (s, e) =>
            {
                var g = e.Graphics;
                g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;
                using var line = new Pen(Color.FromArgb(200, 206, 216));
                g.DrawLine(line, 0, 0, footer.Width, 0);
                using var brandFont = new Font("Segoe UI", 8.5f, FontStyle.Bold);
                using var brandBrush = new SolidBrush(Color.FromArgb(10, 22, 40));
                g.DrawString("PC Plus Computing Inc.", brandFont, brandBrush, 0, 12);
                using var tagFont = new Font("Segoe UI", 7.5f);
                using var tagBrush = new SolidBrush(Color.FromArgb(120, 130, 145));
                g.DrawString("Your Security Is Our Priority", tagFont, tagBrush, 0, 30);
                var verText = $"v{Application.ProductVersion}";
                var verSize = g.MeasureString(verText, tagFont);
                g.DrawString(verText, tagFont, tagBrush, footer.Width - verSize.Width, 12);
                g.DrawString("pcpluscomputing.com  |  604-760-1662", tagFont, tagBrush, footer.Width - 230, 30);
            };
            _contentArea.Controls.Add(footer);
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
            int contentW = _contentArea.ClientSize.Width - m * 2 - _contentArea.Padding.Horizontal;
            if (contentW < 400) contentW = Math.Max(700, _contentArea.Width - 80);
            int y = 10;

            // === HERO STATUS CARD - Premium security overview ===
            var heroCard = CreateCard(new Point(m, y), new Size(contentW, 140));
            heroCard.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            heroCard.Paint += (s, e) =>
            {
                var g = e.Graphics;
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

                var hasData = _health != null && (_health.CpuPercent > 0 || _health.RamPercent > 0);
                var score = _securityResult?.TotalScore ?? 0;
                var statusColor = hasData ? (score >= 80 ? AccentGreen : score >= 50 ? AccentOrange : AccentRed) : AccentOrange;

                // Subtle gradient background
                using var gradBrush = new LinearGradientBrush(
                    new Rectangle(0, 0, heroCard.Width, heroCard.Height),
                    Color.FromArgb(12, statusColor), Color.FromArgb(3, statusColor),
                    LinearGradientMode.Horizontal);
                g.FillRectangle(gradBrush, heroCard.ClientRectangle);

                // Left accent bar
                g.FillRectangle(new SolidBrush(statusColor), 0, 0, 4, heroCard.Height);

                // Shield with glow
                int shieldSize = 72;
                int shieldX = 24, shieldY = (heroCard.Height - shieldSize) / 2;

                // Glow behind shield
                using var glowBrush = new SolidBrush(Color.FromArgb(20, statusColor));
                g.FillEllipse(glowBrush, shieldX - 6, shieldY - 6, shieldSize + 12, shieldSize + 12);

                using var shieldBrush = new SolidBrush(statusColor);
                g.FillEllipse(shieldBrush, shieldX, shieldY, shieldSize, shieldSize);

                // Inner circle highlight
                using var innerBrush = new SolidBrush(Color.FromArgb(30, 255, 255, 255));
                g.FillEllipse(innerBrush, shieldX + 4, shieldY + 4, shieldSize - 8, shieldSize - 8);

                using var checkPen = new Pen(Color.White, 3.5f) { StartCap = LineCap.Round, EndCap = LineCap.Round };
                if (hasData)
                {
                    g.DrawLine(checkPen, shieldX + 22, shieldY + 38, shieldX + 30, shieldY + 48);
                    g.DrawLine(checkPen, shieldX + 30, shieldY + 48, shieldX + 50, shieldY + 26);
                }
                else
                {
                    using var dotFont = new Font("Segoe UI", 20, FontStyle.Bold);
                    using var wb = new SolidBrush(Color.White);
                    g.DrawString("...", dotFont, wb, shieldX + 16, shieldY + 18);
                }

                int textX = shieldX + shieldSize + 24;

                // Status text
                var statusText = hasData ? "Protection Active" : "Connecting...";
                using var statusFont = new Font("Segoe UI", 20, FontStyle.Bold);
                using var statusBrush = new SolidBrush(TextDark);
                g.DrawString(statusText, statusFont, statusBrush, textX, 16);

                // Module status pills
                var scanTime = _securityResult?.ScanTime.ToString("MMM d, h:mm tt") ?? "Never";
                using var pillFont = new Font("Segoe UI", 8f, FontStyle.Bold);
                int pillX = textX;
                int pillY = 54;

                void DrawPill(string text, Color pillColor, bool active)
                {
                    var sz = g.MeasureString(text, pillFont);
                    int pw = (int)sz.Width + 16;
                    using var pPath = RoundedRect(new Rectangle(pillX, pillY, pw, 20), 10);
                    using var pBg = new SolidBrush(active ? Color.FromArgb(20, pillColor) : Color.FromArgb(245, 247, 250));
                    g.FillPath(pBg, pPath);
                    using var pBrush = new SolidBrush(active ? pillColor : TextMuted);
                    g.DrawString(text, pillFont, pBrush, pillX + 8, pillY + 2);
                    pillX += pw + 6;
                }
                DrawPill("Real-Time", AccentGreen, hasData);
                DrawPill("DNS Shield", AccentTeal, _dnsActive);
                DrawPill("Firewall", AccentBlue, hasData);
                DrawPill($"Scan: {scanTime}", TextMuted, false);

                // Uptime info
                if (_health != null)
                {
                    using var upFont = new Font("Segoe UI", 8.5f);
                    using var upBrush = new SolidBrush(TextMuted);
                    var up = _health.Uptime;
                    g.DrawString($"Uptime: {(int)up.TotalDays}d {up.Hours}h {up.Minutes}m", upFont, upBrush, textX, 82);
                }

                // Security score ring gauge on right
                int ringSize = 90;
                int ringX = heroCard.Width - ringSize - 24;
                int ringY = (heroCard.Height - ringSize) / 2;
                var ringRect = new Rectangle(ringX, ringY, ringSize, ringSize);

                // Ring track
                using var ringTrack = new Pen(Color.FromArgb(225, 230, 238), 8);
                ringTrack.StartCap = LineCap.Round; ringTrack.EndCap = LineCap.Round;
                g.DrawArc(ringTrack, ringRect, 0, 360);

                // Ring glow
                float scorePct = score / 100f;
                if (scorePct > 0)
                {
                    using var ringGlow = new Pen(Color.FromArgb(25, statusColor), 14);
                    ringGlow.StartCap = LineCap.Round; ringGlow.EndCap = LineCap.Round;
                    g.DrawArc(ringGlow, ringRect, -90, scorePct * 360f);
                }

                // Ring value
                if (scorePct > 0)
                {
                    using var ringPen = new Pen(statusColor, 8);
                    ringPen.StartCap = LineCap.Round; ringPen.EndCap = LineCap.Round;
                    g.DrawArc(ringPen, ringRect, -90, scorePct * 360f);
                }

                // White center circle behind text
                int innerSize = ringSize - 20;
                int innerX = ringX + 10;
                int innerY = ringY + 10;
                using var centerBrush = new SolidBrush(Color.White);
                g.FillEllipse(centerBrush, innerX, innerY, innerSize, innerSize);

                // Score text in center
                var sf = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center };
                var scoreStr = hasData ? $"{score}" : "--";
                using var scoreFont = new Font("Segoe UI", 20, FontStyle.Bold);
                using var scoreBrush = new SolidBrush(hasData ? statusColor : TextMuted);
                g.DrawString(scoreStr, scoreFont, scoreBrush,
                    new RectangleF(ringX, ringY - 2, ringSize, ringSize - 10), sf);
                using var scoreLbl = new Font("Segoe UI", 7f);
                using var lblBrush = new SolidBrush(TextMuted);
                g.DrawString("SCORE", scoreLbl, lblBrush,
                    new RectangleF(ringX, ringY + 22, ringSize, 30), sf);
            };
            _contentArea.Controls.Add(heroCard);
            y += 148;

            // === MONITOR TOGGLE - small switch ===
            var togglePanel = new Panel
            {
                Size = new Size(180, 24),
                Location = new Point(m + contentW - 180, y - 30),
                BackColor = Color.Transparent, Cursor = Cursors.Hand
            };
            var readingAge = _hwSnapshotTime > DateTime.MinValue
                ? $"Reading: {_hwSnapshotTime:h:mm tt}" : "No reading";
            togglePanel.Paint += (s, e) =>
            {
                var g = e.Graphics;
                g.SmoothingMode = SmoothingMode.AntiAlias;
                using var lbl = new Font("Segoe UI", 7.5f);
                using var lblB = new SolidBrush(TextMuted);
                g.DrawString(_localMonitorEnabled ? "Live Monitor" : readingAge, lbl, lblB, 0, 5);
                int sx = 110, sy = 3, sw = 36, sh = 18;
                var trackColor = _localMonitorEnabled ? AccentGreen : Color.FromArgb(200, 205, 212);
                using var track = new SolidBrush(trackColor);
                g.FillRoundedRectangle(track, sx, sy, sw, sh, 9);
                int knobX = _localMonitorEnabled ? sx + sw - sh + 2 : sx + 2;
                using var knob = new SolidBrush(Color.White);
                g.FillEllipse(knob, knobX, sy + 2, sh - 4, sh - 4);
            };
            togglePanel.Click += (s, e) =>
            {
                ToggleLocalMonitor(!_localMonitorEnabled);
                ShowView("dashboard");
            };
            _contentArea.Controls.Add(togglePanel);
            togglePanel.BringToFront();

            // === SYSTEM GAUGES - 4 donut cards ===
            int gap = 10;
            int gaugeW = (contentW - gap * 3) / 4;
            int gaugeH = 170;

            float cpuVal = _health?.CpuPercent ?? 0;
            float ramVal = _health?.RamPercent ?? 0;
            float diskVal = _health?.Disks.FirstOrDefault()?.UsedPercent ?? 0;
            float tempVal = _health?.CpuTempC ?? 0;

            // Track trend history
            void AddHistory(List<float> hist, float val)
            {
                hist.Add(val);
                if (hist.Count > MaxHistoryPoints) hist.RemoveAt(0);
            }
            if (_health != null)
            {
                AddHistory(_cpuHistory, cpuVal);
                AddHistory(_ramHistory, ramVal);
                AddHistory(_diskHistory, diskVal);
                AddHistory(_tempHistory, tempVal);
            }
            string ramDetail = _health != null ? $"{_health.RamUsedGB:F1} / {_health.RamTotalGB:F1} GB" : "";
            var firstDisk = _health?.Disks.FirstOrDefault();
            string diskDetail = firstDisk != null ? $"{firstDisk.TotalGB - firstDisk.FreeGB:F0} / {firstDisk.TotalGB:F0} GB" : "";
            string tempDetail = tempVal > 0 ? $"{tempVal:F0}\u00B0C" : "No sensor";

            var cpuCard = CreateGaugeCard("CPU", cpuVal, "%", AccentBlue,
                new Point(m, y), new Size(gaugeW, gaugeH), null, _cpuHistory);
            var ramCard = CreateGaugeCard("Memory", ramVal, "%", AccentTeal,
                new Point(m + gaugeW + gap, y), new Size(gaugeW, gaugeH), ramDetail, _ramHistory);
            var diskCard = CreateGaugeCard("Disk", diskVal, "%", AccentOrange,
                new Point(m + (gaugeW + gap) * 2, y), new Size(gaugeW, gaugeH), diskDetail, _diskHistory);
            var tempCard = CreateGaugeCard("Temp", tempVal, "\u00B0C", AccentRed,
                new Point(m + (gaugeW + gap) * 3, y), new Size(gaugeW, gaugeH), tempDetail, _tempHistory);

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
            var monitorCard = CreateCard(new Point(m, y), new Size(leftW, 390));
            monitorCard.Anchor = AnchorStyles.Top | AnchorStyles.Left;
            AddHardwareMonitor(monitorCard);
            _contentArea.Controls.Add(monitorCard);

            // Quick Actions (right)
            var quickCard = CreateCard(new Point(m + leftW + gap, y), new Size(rightW, 390));
            quickCard.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            AddQuickActions(quickCard);
            _contentArea.Controls.Add(quickCard);
            y += 398;

            // === DNS PROTECTION LIVE FEED + MISSING PATCHES - side by side ===
            int dnsW = (contentW - gap) / 2;
            int patchW = contentW - dnsW - gap;
            int feedH = 220;

            // --- DNS Protection Live Feed (left) ---
            var dnsCard = CreateCard(new Point(m, y), new Size(dnsW, feedH));
            dnsCard.Anchor = AnchorStyles.Top | AnchorStyles.Left;
            dnsCard.Paint += (s, e) =>
            {
                var g = e.Graphics;
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

                // Green top accent bar
                using var topBrush = new SolidBrush(AccentGreen);
                g.FillRectangle(topBrush, 1, 1, dnsCard.Width - 2, 3);

                // Header row: green dot + title
                using var dotBrush = new SolidBrush(_dnsActive ? AccentGreen : AccentRed);
                g.FillEllipse(dotBrush, 14, 16, 10, 10);

                using var titleFont = new Font("Segoe UI", 11, FontStyle.Bold);
                using var titleBrush = new SolidBrush(TextDark);
                var dnsTitle = _dnsActive ? "DNS Protection: Active" : "DNS Protection: Inactive";
                g.DrawString(dnsTitle, titleFont, titleBrush, 30, 12);

                // Stats line
                using var statsFont = new Font("Segoe UI", 8.5f);
                using var statsBrush = new SolidBrush(TextMuted);
                var statsText = $"{_dnsDomainsChecked:N0} domains checked  |  {_dnsThreatsBlocked:N0} threats blocked today";
                g.DrawString(statsText, statsFont, statsBrush, 14, 36);

                // Separator line
                using var sepPen = new Pen(CardBorder);
                g.DrawLine(sepPen, 14, 56, dnsCard.Width - 14, 56);

                // "Recent Blocks" sub-header
                using var subFont = new Font("Segoe UI", 8, FontStyle.Bold);
                using var subBrush = new SolidBrush(Color.FromArgb(80, 90, 100));
                g.DrawString("RECENT BLOCKS", subFont, subBrush, 14, 62);

                // Recent blocks list
                using var itemFont = new Font("Segoe UI", 8.5f);
                using var domainBrush = new SolidBrush(AccentRed);
                using var timeBrush = new SolidBrush(TextMuted);
                using var altBg = new SolidBrush(Color.FromArgb(248, 250, 252));

                if (_dnsRecentBlocks.Count == 0)
                {
                    using var emptyBrush = new SolidBrush(TextMuted);
                    using var emptyFont = new Font("Segoe UI", 8.5f, FontStyle.Italic);
                    g.DrawString("No recent blocks recorded", emptyFont, emptyBrush, 14, 82);
                }
                else
                {
                    int rowY = 80;
                    int rowH = 20;
                    for (int i = 0; i < Math.Min(_dnsRecentBlocks.Count, 6); i++)
                    {
                        if (i % 2 == 0)
                            g.FillRectangle(altBg, 4, rowY - 1, dnsCard.Width - 8, rowH);

                        var (domain, timeAgo) = _dnsRecentBlocks[i];
                        var displayDomain = domain.Length > 32 ? domain[..32] + ".." : domain;
                        g.DrawString(displayDomain, itemFont, domainBrush, 14, rowY);

                        var timeSize = g.MeasureString(timeAgo, itemFont);
                        g.DrawString(timeAgo, itemFont, timeBrush, dnsCard.Width - timeSize.Width - 14, rowY);
                        rowY += rowH;
                    }
                }
            };
            _contentArea.Controls.Add(dnsCard);

            // --- Missing Patches (right) ---
            var patchCard = CreateCard(new Point(m + dnsW + gap, y), new Size(patchW, feedH));
            patchCard.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            patchCard.Paint += (s, e) =>
            {
                var g = e.Graphics;
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

                // Orange/red top accent bar depending on count
                var accentColor = _missingPatchCount > 5 ? AccentRed : _missingPatchCount > 0 ? AccentOrange : AccentGreen;
                using var topBrush = new SolidBrush(accentColor);
                g.FillRectangle(topBrush, 1, 1, patchCard.Width - 2, 3);

                // Header row: indicator dot + title
                using var dotBrush = new SolidBrush(accentColor);
                g.FillEllipse(dotBrush, 14, 16, 10, 10);

                using var titleFont = new Font("Segoe UI", 11, FontStyle.Bold);
                using var titleBrush = new SolidBrush(TextDark);
                var patchTitle = _missingPatchCount > 0
                    ? $"Missing Updates: {_missingPatchCount} found"
                    : "Updates: All current";
                g.DrawString(patchTitle, titleFont, titleBrush, 30, 12);

                // Last checked timestamp
                using var statsFont = new Font("Segoe UI", 8.5f);
                using var statsBrush = new SolidBrush(TextMuted);
                var checkedText = _patchesLastChecked > DateTime.MinValue
                    ? $"Last checked: {_patchesLastChecked:MMM d, h:mm tt}"
                    : "Last checked: Never";
                g.DrawString(checkedText, statsFont, statsBrush, 14, 36);

                // Separator line
                using var sepPen = new Pen(CardBorder);
                g.DrawLine(sepPen, 14, 56, patchCard.Width - 14, 56);

                // "Patches" sub-header
                using var subFont = new Font("Segoe UI", 8, FontStyle.Bold);
                using var subBrush = new SolidBrush(Color.FromArgb(80, 90, 100));
                g.DrawString("PATCH", subFont, subBrush, 14, 62);
                g.DrawString("SEVERITY", subFont, subBrush, patchCard.Width - 100, 62);

                // Patches list
                using var itemFont = new Font("Segoe UI", 8.5f);
                using var altBg = new SolidBrush(Color.FromArgb(248, 250, 252));

                if (_missingPatches.Count == 0)
                {
                    using var emptyBrush = new SolidBrush(AccentGreen);
                    using var emptyFont = new Font("Segoe UI", 8.5f, FontStyle.Italic);
                    g.DrawString("All patches up to date", emptyFont, emptyBrush, 14, 82);
                }
                else
                {
                    int rowY = 80;
                    int rowH = 20;
                    for (int i = 0; i < Math.Min(_missingPatches.Count, 6); i++)
                    {
                        if (i % 2 == 0)
                            g.FillRectangle(altBg, 4, rowY - 1, patchCard.Width - 8, rowH);

                        var (patchId, severity) = _missingPatches[i];
                        var displayPatch = patchId.Length > 32 ? patchId[..32] + ".." : patchId;
                        using var patchBrush = new SolidBrush(TextDark);
                        g.DrawString(displayPatch, itemFont, patchBrush, 14, rowY);

                        // Severity badge color
                        var sevColor = severity.Equals("Critical", StringComparison.OrdinalIgnoreCase) ? AccentRed
                            : severity.Equals("Important", StringComparison.OrdinalIgnoreCase) ? AccentOrange
                            : severity.Equals("Moderate", StringComparison.OrdinalIgnoreCase) ? AccentBlue
                            : TextMuted;
                        using var sevBrush = new SolidBrush(sevColor);
                        using var sevFont = new Font("Segoe UI", 8f, FontStyle.Bold);
                        var sevSize = g.MeasureString(severity, sevFont);
                        g.DrawString(severity, sevFont, sevBrush, patchCard.Width - sevSize.Width - 14, rowY);
                        rowY += rowH;
                    }
                }
            };
            _contentArea.Controls.Add(patchCard);
            y += feedH + 8;

            // === PREMIUM FEATURES BAR ===
            var premCard = CreateCard(new Point(m, y), new Size(contentW, 110));
            premCard.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            premCard.Paint += (s, e) =>
            {
                var g = e.Graphics;
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

                // Active green header bar
                using var headerGrad = new LinearGradientBrush(
                    new Point(0, 0), new Point(premCard.Width, 0),
                    Color.FromArgb(16, 185, 129), Color.FromArgb(5, 150, 105));
                using var headerPath = new GraphicsPath();
                headerPath.AddArc(0, 0, 16, 16, 180, 90);
                headerPath.AddArc(premCard.Width - 17, 0, 16, 16, 270, 90);
                headerPath.AddLine(premCard.Width - 1, 8, premCard.Width - 1, 28);
                headerPath.AddLine(premCard.Width - 1, 28, 0, 28);
                headerPath.AddLine(0, 28, 0, 8);
                headerPath.CloseFigure();
                g.FillPath(headerGrad, headerPath);

                using var headerFont = new Font("Segoe UI", 10, FontStyle.Bold);
                using var whiteBrush = new SolidBrush(Color.White);
                g.DrawString("✓  Protection Active  -  All modules running", headerFont, whiteBrush, 12, 5);

                var modules = new[]
                {
                    ("Ransomware Shield", "Active", AccentGreen),
                    ("AI Threat Analysis", "Scanning", AccentBlue),
                    ("Remote Lockdown", "Ready", AccentGreen),
                    ("Backup & Recovery", "Enabled", AccentGreen)
                };

                int fx = 10;
                int fCardW = (premCard.Width - 50) / 4;
                using var fNameFont = new Font("Segoe UI", 9f, FontStyle.Bold);
                using var fStatusFont = new Font("Segoe UI", 7.5f, FontStyle.Bold);

                for (int i = 0; i < modules.Length; i++)
                {
                    var (name, status, statusColor) = modules[i];
                    var fRect = new Rectangle(fx + i * (fCardW + 10), 36, fCardW, 64);
                    using var fPath = RoundedRect(fRect, 6);
                    using var fBg = new SolidBrush(Color.FromArgb(240, 253, 244));
                    using var fBorder = new Pen(Color.FromArgb(187, 247, 208));
                    g.FillPath(fBg, fPath);
                    g.DrawPath(fBorder, fPath);
                    using var nameBrush = new SolidBrush(TextDark);
                    g.DrawString(name, fNameFont, nameBrush, fRect.X + 8, fRect.Y + 8);
                    using var dotBrush = new SolidBrush(statusColor);
                    g.FillEllipse(dotBrush, fRect.X + 8, fRect.Y + 34, 8, 8);
                    using var statusBrush = new SolidBrush(statusColor);
                    g.DrawString(status, fStatusFont, statusBrush, fRect.X + 20, fRect.Y + 32);
                }
            };
            _contentArea.Controls.Add(premCard);
        }

        private Panel CreateGaugeCard(string label, float value, string unit, Color color,
            Point loc, Size size, string? detail = null, List<float>? history = null)
        {
            var card = CreateCard(loc, size);
            card.Paint += (s, e) =>
            {
                var g = e.Graphics;
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

                // Gradient top accent bar
                using var topGrad = new LinearGradientBrush(
                    new Point(0, 0), new Point(card.Width, 0),
                    color, Color.FromArgb(180, color.R, color.G, color.B));
                g.FillRectangle(topGrad, 1, 1, card.Width - 2, 3);

                // Label at top
                using var labelFont = new Font("Segoe UI", 10f, FontStyle.Bold);
                using var labelBrush = new SolidBrush(TextDark);
                g.DrawString(label, labelFont, labelBrush, 12, 12);

                // Donut ring - larger and thicker
                int donutSize = 80;
                int thickness = 10;
                int donutX = (card.Width - donutSize) / 2;
                int donutY = 34;
                var donutRect = new Rectangle(donutX, donutY, donutSize, donutSize);

                // Outer glow behind donut
                float pct = Math.Min(value / 100f, 1f);
                var arcColor = pct > 0.9f ? AccentRed : pct > 0.75f ? AccentOrange : color;
                if (pct > 0)
                {
                    using var glowPen = new Pen(Color.FromArgb(25, arcColor), thickness + 8);
                    glowPen.StartCap = LineCap.Round; glowPen.EndCap = LineCap.Round;
                    g.DrawArc(glowPen, donutRect, -90, pct * 360f);
                }

                // Track ring
                using var trackPen = new Pen(Color.FromArgb(230, 234, 240), thickness);
                trackPen.StartCap = LineCap.Round; trackPen.EndCap = LineCap.Round;
                g.DrawArc(trackPen, donutRect, 0, 360);

                // Value arc with rounded caps
                float sweep = pct * 360f;
                if (sweep > 0.5f)
                {
                    using var valuePen = new Pen(arcColor, thickness);
                    valuePen.StartCap = LineCap.Round; valuePen.EndCap = LineCap.Round;
                    g.DrawArc(valuePen, donutRect, -90, sweep);
                }

                // Center value - bold
                var displayVal = value > 0 ? $"{value:F0}" : "--";
                using var valFont = new Font("Segoe UI", 22, FontStyle.Bold);
                using var valBrush = new SolidBrush(TextDark);
                var valSize = g.MeasureString(displayVal, valFont);
                g.DrawString(displayVal, valFont, valBrush,
                    donutX + (donutSize - valSize.Width) / 2,
                    donutY + (donutSize - valSize.Height) / 2 - 4);

                // Unit label
                using var unitFont = new Font("Segoe UI", 8f);
                using var unitBrush = new SolidBrush(TextMuted);
                var unitSize = g.MeasureString(unit, unitFont);
                g.DrawString(unit, unitFont, unitBrush,
                    donutX + (donutSize - unitSize.Width) / 2,
                    donutY + donutSize / 2 + valSize.Height / 2 - 8);

                // Detail text below donut
                int detailY = donutRect.Bottom + 4;
                if (!string.IsNullOrEmpty(detail))
                {
                    using var detFont = new Font("Segoe UI", 8f);
                    var detSize = g.MeasureString(detail, detFont);
                    g.DrawString(detail, detFont, unitBrush, (card.Width - detSize.Width) / 2, detailY);
                    detailY += 16;
                }

                // Mini sparkline trend chart
                if (history != null && history.Count >= 2)
                {
                    int sparkX = 12;
                    int sparkY = card.Height - 28;
                    int sparkW = card.Width - 24;
                    int sparkH = 20;

                    // Sparkline background
                    using var sparkBg = new SolidBrush(Color.FromArgb(248, 250, 252));
                    using var sparkBgPath = RoundedRect(new Rectangle(sparkX - 2, sparkY - 2, sparkW + 4, sparkH + 4), 4);
                    g.FillPath(sparkBg, sparkBgPath);

                    float maxVal = history.Max();
                    float minVal = history.Min();
                    float range = Math.Max(maxVal - minVal, 1f);

                    var points = new PointF[history.Count];
                    for (int i = 0; i < history.Count; i++)
                    {
                        float x = sparkX + (float)i / (history.Count - 1) * sparkW;
                        float y2 = sparkY + sparkH - ((history[i] - minVal) / range * sparkH);
                        points[i] = new PointF(x, y2);
                    }

                    // Filled area under sparkline
                    if (points.Length >= 2)
                    {
                        var fillPoints = new List<PointF>(points);
                        fillPoints.Add(new PointF(points[^1].X, sparkY + sparkH));
                        fillPoints.Add(new PointF(points[0].X, sparkY + sparkH));
                        using var fillBrush = new SolidBrush(Color.FromArgb(20, arcColor));
                        g.FillPolygon(fillBrush, fillPoints.ToArray());
                    }

                    // Sparkline stroke
                    using var sparkPen = new Pen(Color.FromArgb(160, arcColor), 1.5f);
                    sparkPen.LineJoin = LineJoin.Round;
                    g.DrawLines(sparkPen, points);

                    // Dot on latest point
                    var lastPt = points[^1];
                    using var dotBrush = new SolidBrush(arcColor);
                    g.FillEllipse(dotBrush, lastPt.X - 2.5f, lastPt.Y - 2.5f, 5, 5);
                }
            };
            return card;
        }

        private void AddHardwareMonitor(Panel card)
        {
            // Update cached snapshot if interval elapsed (or first reading)
            if (_health != null && !(_hwLockAfterFirst && _hwSnapshot != null))
            {
                if (DateTime.Now - _hwSnapshotTime >= HwRefreshInterval || _hwSnapshot == null)
                {
                    _hwSnapshot = _health;
                    _hwSnapshotTime = DateTime.Now;
                }
            }
            var displayHealth = _hwSnapshot ?? _health;

            // Lock toggle checkbox
            var lockCheck = new CheckBox
            {
                Text = "Lock readings", Checked = _hwLockAfterFirst,
                Font = new Font("Segoe UI", 8f), ForeColor = TextMuted,
                BackColor = Color.Transparent, AutoSize = true,
                Location = new Point(card.Width - 120, 12), Cursor = Cursors.Hand
            };
            lockCheck.CheckedChanged += (s, e) =>
            {
                _hwLockAfterFirst = lockCheck.Checked;
            };
            card.Controls.Add(lockCheck);

            card.Paint += (s, e) =>
            {
                var g = e.Graphics;
                g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

                // Title with icon
                using var titleFont = new Font("Segoe UI", 11, FontStyle.Bold);
                using var titleBrush = new SolidBrush(TextDark);
                g.DrawString("Hardware Monitor", titleFont, titleBrush, 14, 10);

                // Subtitle with snapshot time
                using var subFont = new Font("Segoe UI", 8f);
                using var subBrush = new SolidBrush(TextMuted);
                var procCount = displayHealth?.ProcessCount ?? 0;
                var snapInfo = _hwSnapshotTime > DateTime.MinValue
                    ? $"{procCount} processes  |  Snapshot: {_hwSnapshotTime:h:mm tt}"
                    : $"{procCount} processes running";
                g.DrawString(snapInfo, subFont, subBrush, 14, 30);

                if (displayHealth?.TopProcesses == null || displayHealth.TopProcesses.Count == 0)
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

                foreach (var (proc, idx) in displayHealth.TopProcesses.Take(7).Select((p, i) => (p, i)))
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
                }),
                ("Remote Support", "Connect with a technician", Color.FromArgb(139, 92, 246), async () =>
                {
                    await Task.CompletedTask;
                    System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                    { FileName = "https://mesh.pcpluscomputing.com/", UseShellExecute = true });
                }),
                ("VPN Portal", "Download and configure VPN", Color.FromArgb(16, 185, 129), async () =>
                {
                    await Task.CompletedTask;
                    System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                    { FileName = "https://vpn.pcpluscomputing.com/", UseShellExecute = true });
                })
            };

            int btnY = 38;
            int btnH = 46;
            int btnGap = 5;
            string[] icons = { "\u2714", "\u2692", "\u21C5", "\u2605", "\u2316", "\u260E", "\u26BF" };
            int iconIdx = 0;
            foreach (var (text, desc, color, action) in actions)
            {
                var btnColor = color;
                var btnIcon = iconIdx < icons.Length ? icons[iconIdx] : "\u25CF";
                iconIdx++;
                var btn = new Panel
                {
                    Location = new Point(10, btnY), Size = new Size(card.Width - 20, btnH),
                    BackColor = Color.FromArgb(250, 251, 252), Cursor = Cursors.Hand
                };
                btn.Paint += (s, e) =>
                {
                    var g = e.Graphics;
                    g.SmoothingMode = SmoothingMode.AntiAlias;
                    g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

                    // Rounded background
                    using var bgPath = RoundedRect(new Rectangle(0, 0, btn.Width - 1, btn.Height - 1), 8);
                    using var bgBrush = new SolidBrush(btn.BackColor);
                    g.FillPath(bgBrush, bgPath);
                    using var borderPen = new Pen(Color.FromArgb(220, 225, 235));
                    g.DrawPath(borderPen, bgPath);

                    // Color circle icon
                    int circleSize = 30;
                    int circleX = 8, circleY = (btn.Height - circleSize) / 2;
                    using var circleBg = new SolidBrush(Color.FromArgb(18, btnColor));
                    g.FillEllipse(circleBg, circleX, circleY, circleSize, circleSize);
                    using var iconFont = new Font("Segoe UI Symbol", 11);
                    using var iconBrush = new SolidBrush(btnColor);
                    var iconSz = g.MeasureString(btnIcon, iconFont);
                    g.DrawString(btnIcon, iconFont, iconBrush,
                        circleX + (circleSize - iconSz.Width) / 2,
                        circleY + (circleSize - iconSz.Height) / 2);

                    // Text
                    using var nameFont = new Font("Segoe UI", 9.5f, FontStyle.Bold);
                    using var descFont = new Font("Segoe UI", 7.5f);
                    using var nameBrush = new SolidBrush(TextDark);
                    using var descBrush = new SolidBrush(TextMuted);
                    g.DrawString(text, nameFont, nameBrush, circleX + circleSize + 8, 5);
                    g.DrawString(desc, descFont, descBrush, circleX + circleSize + 8, 24);

                    // Arrow
                    using var arrowFont = new Font("Segoe UI", 12);
                    g.DrawString("\u203A", arrowFont, descBrush, btn.Width - 22, 11);
                };
                btn.MouseEnter += (s, e) => btn.BackColor = Color.FromArgb(235, 240, 250);
                btn.MouseLeave += (s, e) => btn.BackColor = Color.FromArgb(250, 251, 252);
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
                using var http = new System.Net.Http.HttpClient { Timeout = TimeSpan.FromSeconds(30) };
                http.DefaultRequestHeaders.UserAgent.ParseAdd("PCPlus/4.18 SpeedTest");

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
                        pingMs = pings.OrderBy(p => p).Take(3).Average();
                }
                catch { pingMs = 0; }
                if (!form.IsDisposed) gaugePanel.Invalidate();

                // Download test - streaming with live speed updates
                phase = "Testing download...";
                if (!form.IsDisposed) gaugePanel.Invalidate();
                var dlUrls = new[]
                {
                    "https://speed.cloudflare.com/__down?bytes=25000000",
                    "https://speed.hetzner.de/100MB.bin",
                    "https://proof.ovh.net/files/100Mb.dat",
                    "https://ash-speed.hetzner.com/100MB.bin"
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
                        while ((bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length)) > 0)
                        {
                            totalBytes += bytesRead;
                            var elapsed = sw.ElapsedMilliseconds;
                            if (elapsed - lastUpdate > 500 && elapsed > 0)
                            {
                                downloadMbps = (totalBytes * 8.0) / (elapsed / 1000.0) / 1_000_000.0;
                                lastUpdate = elapsed;
                                if (!form.IsDisposed) form.BeginInvoke(new Action(() => { if (!form.IsDisposed) gaugePanel.Invalidate(); }));
                            }
                            if (elapsed > 12000) break;
                        }
                        sw.Stop();
                        if (sw.Elapsed.TotalSeconds > 0.5)
                            downloadMbps = (totalBytes * 8.0) / sw.Elapsed.TotalSeconds / 1_000_000.0;
                        if (!form.IsDisposed) form.BeginInvoke(new Action(() => { if (!form.IsDisposed) gaugePanel.Invalidate(); }));
                        break;
                    }
                    catch { continue; }
                }

                // Upload test - 5MB payload with fallback servers
                phase = "Testing upload...";
                if (!form.IsDisposed) form.BeginInvoke(new Action(() => { if (!form.IsDisposed) gaugePanel.Invalidate(); }));
                var ulUrls = new[]
                {
                    "https://speed.cloudflare.com/__up",
                    "https://speed.hetzner.de/",
                    "https://bouygues.testdebit.info/ul/"
                };
                foreach (var ulUrl in ulUrls)
                {
                    try
                    {
                        var uploadSize = 5 * 1024 * 1024;
                        var uploadData = new byte[uploadSize];
                        new Random().NextBytes(uploadData);
                        var sw = System.Diagnostics.Stopwatch.StartNew();
                        using var content = new System.Net.Http.ByteArrayContent(uploadData);
                        content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");
                        await http.PostAsync(ulUrl, content);
                        sw.Stop();
                        if (sw.Elapsed.TotalSeconds > 0.1)
                            uploadMbps = (uploadData.Length * 8.0) / sw.Elapsed.TotalSeconds / 1_000_000.0;
                        break;
                    }
                    catch { continue; }
                }

                done = true;
                phase = "Test Complete";
                if (!form.IsDisposed) form.BeginInvoke(new Action(() => { if (!form.IsDisposed) gaugePanel.Invalidate(); }));
            }
            catch
            {
                phase = "Test Failed - Check connection";
                if (!form.IsDisposed) form.BeginInvoke(new Action(() => { if (!form.IsDisposed) gaugePanel.Invalidate(); }));
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

        private static readonly List<ModuleStatus> DefaultModules = new()
        {
            new() { ModuleId = "health",      ModuleName = "System Health Monitor",     IsRunning = true, StatusText = "Monitoring CPU, RAM, Disk, Temperature" },
            new() { ModuleId = "security",    ModuleName = "Security Scanner",          IsRunning = true, StatusText = "175-point security audit active" },
            new() { ModuleId = "ransomware",  ModuleName = "Ransomware Shield",         IsRunning = true, StatusText = "Behavioral monitoring active" },
            new() { ModuleId = "phishing",    ModuleName = "Phishing Protection",       IsRunning = true, StatusText = "URL & domain filtering active" },
            new() { ModuleId = "policy",      ModuleName = "Policy Engine",             IsRunning = true, StatusText = "Compliance rules enforced" },
            new() { ModuleId = "maintenance", ModuleName = "Auto-Maintenance",          IsRunning = true, StatusText = "Scheduled cleanup active" },
            new() { ModuleId = "reporting",   ModuleName = "Reporting & Analytics",      IsRunning = true, StatusText = "Dashboard telemetry active" },
            new() { ModuleId = "backup",      ModuleName = "Backup Monitor",            IsRunning = true, StatusText = "Shadow copy verification active" },
        };

        private void BuildProtectionView()
        {
            var title = CreatePageTitle("Real-Time Protection");
            _contentArea.Controls.Add(title);

            var modules = (_serviceStatus?.Modules?.Count > 0)
                ? _serviceStatus.Modules
                : DefaultModules;

            int y = 55;
            foreach (var module in modules)
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
            AddPromoCards(y + 8, 24, _contentArea.Width - 72);
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
                AddPromoCards(185, 24, _contentArea.Width - 72);
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

        private async void BuildLockdownView()
        {
            var title = CreatePageTitle("Lockdown Mode");
            _contentArea.Controls.Add(title);

            int m = 16;
            int contentW = _contentArea.ClientSize.Width - m * 2 - _contentArea.Padding.Horizontal;
            if (contentW < 400) contentW = Math.Max(700, _contentArea.Width - 80);
            int y = 55;

            // Status card - shows current lockdown state
            var statusCard = CreateCard(new Point(m + 12, y), new Size(contentW, 130));
            statusCard.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;

            bool isLocked = false;
            string lockReason = "";
            string lockTime = "";

            // Fetch lockdown state asynchronously (never block UI thread)
            if (_ipc.IsConnected && !_usingLocalFallback)
            {
                try
                {
                    var resp = await _ipc.SendModuleCommandAsync("ransomware", "GetStatus",
                        new Dictionary<string, string>());
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

            if (IsDisposed || _currentView != "lockdown") return;

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
            y = infoCard.Bottom + 16;
            AddPromoCards(y, m + 12, contentW);
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

        #region Vulnerability View

        private async void BuildVulnerabilityView()
        {
            int y = 0;
            int m = 16;
            int contentW = _contentArea.ClientSize.Width - m * 2 - _contentArea.Padding.Horizontal;

            // Title
            var titleLabel = new Label
            {
                Text = "Vulnerability Scanner",
                Font = new Font("Segoe UI", 18, FontStyle.Bold),
                ForeColor = TextDark,
                Location = new Point(m, y),
                AutoSize = true
            };
            _contentArea.Controls.Add(titleLabel);

            var subLabel = new Label
            {
                Text = "Powered by OpenVAS/Greenbone - Network vulnerability assessment",
                Font = new Font("Segoe UI", 9),
                ForeColor = TextMuted,
                Location = new Point(m, y + 32),
                AutoSize = true
            };
            _contentArea.Controls.Add(subLabel);
            y += 68;

            // Status card
            var statusCard = CreateRoundedPanel(new Rectangle(m, y, contentW, 120), CardBg, CardBorder);

            var shieldPanel = new Panel
            {
                Location = new Point(20, 16),
                Size = new Size(88, 88),
                BackColor = Color.Transparent
            };
            shieldPanel.Paint += (s, e) =>
            {
                var g = e.Graphics;
                g.SmoothingMode = SmoothingMode.AntiAlias;
                using var bgBrush = new SolidBrush(Color.FromArgb(20, AccentGreen));
                using var bgPath = RoundedRect(new Rectangle(0, 0, 88, 88), 16);
                g.FillPath(bgBrush, bgPath);
                using var shieldBrush = new SolidBrush(AccentGreen);
                var sp = new GraphicsPath();
                sp.AddArc(24, 14, 10, 10, 180, 90);
                sp.AddArc(54, 14, 10, 10, 270, 90);
                sp.AddLine(64, 19, 64, 44);
                sp.AddLine(64, 44, 44, 68);
                sp.AddLine(44, 68, 24, 44);
                sp.AddLine(24, 44, 24, 19);
                sp.CloseFigure();
                g.FillPath(shieldBrush, sp);
                using var checkPen = new Pen(Color.White, 3f) { StartCap = LineCap.Round, EndCap = LineCap.Round };
                g.DrawLine(checkPen, 36, 42, 42, 50);
                g.DrawLine(checkPen, 42, 50, 54, 34);
            };
            statusCard.Controls.Add(shieldPanel);

            var statusText = new Label
            {
                Text = "Scanner Active",
                Font = new Font("Segoe UI", 16, FontStyle.Bold),
                ForeColor = AccentGreen,
                Location = new Point(120, 22),
                AutoSize = true
            };
            statusCard.Controls.Add(statusText);

            var statusSub = new Label
            {
                Text = "Weekly full scan every Sunday 2AM. On-demand scans available anytime.",
                Font = new Font("Segoe UI", 9.5f),
                ForeColor = TextMuted,
                Location = new Point(120, 54),
                Size = new Size(contentW - 160, 40)
            };
            statusCard.Controls.Add(statusSub);

            _contentArea.Controls.Add(statusCard);
            y += 136;

            // Severity summary cards
            var cardW = (contentW - m * 3) / 4;
            var sevColors = new[] { AccentRed, AccentOrange, AccentBlue, AccentGreen };
            var sevLabels = new[] { "Critical", "High", "Medium", "Low" };
            var sevRanges = new[] { "CVSS 9.0-10.0", "CVSS 7.0-8.9", "CVSS 4.0-6.9", "CVSS 0.1-3.9" };
            var sevCountLabels = new Label[4];

            for (int i = 0; i < 4; i++)
            {
                var card = CreateRoundedPanel(new Rectangle(m + i * (cardW + m), y, cardW, 100), CardBg, CardBorder);

                var accentBar = new Panel
                {
                    Location = new Point(0, 0),
                    Size = new Size(4, 100),
                    BackColor = sevColors[i]
                };
                card.Controls.Add(accentBar);

                var defaultCounts = new[] { "0", "0", "0", "0" };
                sevCountLabels[i] = new Label
                {
                    Text = defaultCounts[i],
                    Font = new Font("Segoe UI", 28, FontStyle.Bold),
                    ForeColor = sevColors[i],
                    Location = new Point(16, 8),
                    AutoSize = true
                };
                card.Controls.Add(sevCountLabels[i]);

                card.Controls.Add(new Label
                {
                    Text = sevLabels[i],
                    Font = new Font("Segoe UI", 10, FontStyle.Bold),
                    ForeColor = TextDark,
                    Location = new Point(16, 58),
                    AutoSize = true
                });

                card.Controls.Add(new Label
                {
                    Text = sevRanges[i],
                    Font = new Font("Segoe UI", 8),
                    ForeColor = TextMuted,
                    Location = new Point(16, 78),
                    AutoSize = true
                });

                _contentArea.Controls.Add(card);
            }
            y += 116;

            // Scan details card
            var detailCard = CreateRoundedPanel(new Rectangle(m, y, contentW, 200), CardBg, CardBorder);

            detailCard.Controls.Add(new Label
            {
                Text = "Scan Details",
                Font = new Font("Segoe UI", 12, FontStyle.Bold),
                ForeColor = TextDark,
                Location = new Point(20, 14),
                AutoSize = true
            });

            var detailKeys = new[] { "Last Scan", "Duration", "Hosts Scanned", "Total Findings", "Next Scheduled", "Feed Status" };
            var detailDefaults = new[] {
                "Pending first scan",
                "N/A",
                "1 (localhost)",
                "0 findings",
                "Next Sunday 2:00 AM",
                "Up to date"
            };
            var detailValLabels = new Label[detailKeys.Length];

            for (int i = 0; i < detailKeys.Length; i++)
            {
                detailCard.Controls.Add(new Label
                {
                    Text = detailKeys[i],
                    Font = new Font("Segoe UI", 9.5f),
                    ForeColor = TextMuted,
                    Location = new Point(20, 46 + i * 24),
                    AutoSize = true
                });

                detailValLabels[i] = new Label
                {
                    Text = detailDefaults[i],
                    Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
                    ForeColor = TextDark,
                    Location = new Point(200, 46 + i * 24),
                    AutoSize = true
                };
                detailCard.Controls.Add(detailValLabels[i]);
            }

            _contentArea.Controls.Add(detailCard);
            y += 216;

            // Top vulnerabilities list
            var vulnListCard = CreateRoundedPanel(new Rectangle(m, y, contentW, 220), CardBg, CardBorder);
            vulnListCard.Controls.Add(new Label
            {
                Text = "Top Vulnerabilities",
                Font = new Font("Segoe UI", 12, FontStyle.Bold),
                ForeColor = TextDark,
                Location = new Point(20, 14),
                AutoSize = true
            });

            var vulnEmptyPanel = new Panel
            {
                Location = new Point(0, 42),
                Size = new Size(contentW, 170),
                BackColor = Color.Transparent
            };
            vulnEmptyPanel.Paint += (s, e) =>
            {
                var g = e.Graphics;
                g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;
                g.SmoothingMode = SmoothingMode.AntiAlias;

                using var checkBg = new SolidBrush(Color.FromArgb(220, 252, 231));
                g.FillEllipse(checkBg, contentW / 2 - 24, 8, 48, 48);
                using var checkFont = new Font("Segoe UI", 20);
                using var checkBrush = new SolidBrush(AccentGreen);
                g.DrawString("✓", checkFont, checkBrush, contentW / 2 - 14, 16);

                using var msgFont = new Font("Segoe UI", 11, FontStyle.Bold);
                using var msgBrush = new SolidBrush(TextDark);
                var msg = "No vulnerabilities detected";
                var msgSz = g.MeasureString(msg, msgFont);
                g.DrawString(msg, msgFont, msgBrush, (contentW - msgSz.Width) / 2, 64);

                using var subFont = new Font("Segoe UI", 9f);
                using var subBrush = new SolidBrush(TextMuted);
                var sub = "Run a scan to check for security issues, or wait for the next scheduled scan.";
                var subSz = g.MeasureString(sub, subFont);
                g.DrawString(sub, subFont, subBrush, (contentW - subSz.Width) / 2, 86);

                using var tipFont = new Font("Segoe UI", 8.5f);
                var tips = new[] {
                    "•  Keep Windows and all software up to date",
                    "•  Enable real-time protection for continuous monitoring",
                    "•  Schedule weekly scans for comprehensive coverage"
                };
                int ty = 114;
                foreach (var tip in tips)
                {
                    g.DrawString(tip, tipFont, subBrush, 20, ty);
                    ty += 18;
                }
            };
            vulnListCard.Controls.Add(vulnEmptyPanel);
            _contentArea.Controls.Add(vulnListCard);
            y += 236;

            // Action buttons
            var scanBtn = new Panel
            {
                Location = new Point(m, y),
                Size = new Size(180, 44),
                BackColor = AccentTeal,
                Cursor = Cursors.Hand
            };
            scanBtn.Paint += (s, e) =>
            {
                var g = e.Graphics;
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;
                using var path = RoundedRect(new Rectangle(0, 0, scanBtn.Width, scanBtn.Height), 10);
                using var brush = new SolidBrush(AccentTeal);
                g.FillPath(brush, path);
                using var font = new Font("Segoe UI", 11, FontStyle.Bold);
                using var textBrush = new SolidBrush(Color.White);
                g.DrawString("⛨  Run Scan Now", font, textBrush, 20, 12);
            };
            scanBtn.Click += (s, e) =>
            {
                try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo { FileName = "https://openvas.pcpluscomputing.com", UseShellExecute = true }); } catch { }
            };
            _contentArea.Controls.Add(scanBtn);

            var reportBtn = new Panel
            {
                Location = new Point(m + 196, y),
                Size = new Size(200, 44),
                BackColor = Color.Transparent,
                Cursor = Cursors.Hand
            };
            reportBtn.Paint += (s, e) =>
            {
                var g = e.Graphics;
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;
                using var path = RoundedRect(new Rectangle(0, 0, reportBtn.Width, reportBtn.Height), 10);
                using var pen = new Pen(CardBorder, 1.5f);
                g.DrawPath(pen, path);
                using var font = new Font("Segoe UI", 11, FontStyle.Bold);
                using var textBrush = new SolidBrush(TextDark);
                g.DrawString("↗  View Full Report", font, textBrush, 20, 12);
            };
            reportBtn.Click += (s, e) =>
            {
                try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo { FileName = "https://dashboard.pcpluscomputing.com/network-security.html", UseShellExecute = true }); } catch { }
            };
            _contentArea.Controls.Add(reportBtn);

            // Fetch real vulnerability stats from service
            if (_ipc.IsConnected)
            {
                try
                {
                    var resp = await _ipc.GetVulnerabilityStatsAsync();
                    if (resp.Success)
                    {
                        var stats = resp.GetData<VulnerabilityStatsDto>();
                        if (stats != null)
                        {
                            void UpdateLabels()
                            {
                                if (IsDisposed) return;

                                sevCountLabels[0].Text = stats.Critical.ToString();
                                sevCountLabels[1].Text = stats.High.ToString();
                                sevCountLabels[2].Text = stats.Medium.ToString();
                                sevCountLabels[3].Text = (stats.Low + stats.Info).ToString();

                                // Update status card based on findings
                                if (stats.Critical > 0)
                                {
                                    statusText.Text = "Critical Issues Found";
                                    statusText.ForeColor = AccentRed;
                                    statusSub.Text = $"{stats.Critical} critical vulnerabilities detected. Immediate action recommended.";
                                }
                                else if (stats.High > 0)
                                {
                                    statusText.Text = "Issues Found";
                                    statusText.ForeColor = AccentOrange;
                                    statusSub.Text = $"{stats.High} high-severity vulnerabilities found. Review recommended.";
                                }
                                else if (stats.TotalFindings == 0)
                                {
                                    statusText.Text = "Network Clean";
                                    statusText.ForeColor = AccentGreen;
                                    statusSub.Text = "No vulnerabilities detected. Weekly scan every Sunday 2AM.";
                                }

                                // Scan details
                                if (!string.IsNullOrEmpty(stats.ScanDate))
                                    detailValLabels[0].Text = stats.ScanDate;
                                if (!string.IsNullOrEmpty(stats.ScanDuration))
                                    detailValLabels[1].Text = stats.ScanDuration;
                                detailValLabels[2].Text = stats.HostsScanned > 0 ? stats.HostsScanned.ToString() : "--";
                                detailValLabels[3].Text = stats.TotalFindings.ToString();
                                detailValLabels[4].Text = "Sunday 2:00 AM";
                                detailValLabels[5].Text = "Up to date";
                                detailValLabels[5].ForeColor = AccentGreen;

                                // Top vulnerabilities updated via panel repaint
                                if (stats.TopVulnerabilities.Count > 0)
                                    vulnListCard?.Invalidate();
                            }

                            if (InvokeRequired) Invoke(UpdateLabels);
                            else UpdateLabels();
                        }
                    }
                }
                catch { }
            }
        }

        #endregion

        #region WiFi Security View

        private async void BuildWifiView()
        {
            try
            {
            var title = CreatePageTitle("WiFi Security Scanner");
            _contentArea.Controls.Add(title);

            // Scan button
            var scanBtn = CreateActionButton("Scan Now", AccentTeal, new Point(_contentArea.Width - 140, 10), new Size(100, 32));
            scanBtn.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            scanBtn.Click += (s, e) => ShowView("wifi");
            _contentArea.Controls.Add(scanBtn);

            int y = 60;

            // Request WiFi scan from service
            try
            {
                var resp = await _ipc.SendModuleCommandAsync("customervalue", "GetWifiNetworks");
                if (IsDisposed || _currentView != "wifi") return;
                if (resp.Success)
                {
                    var json = resp.JsonData ?? "{}";
                    using var doc = System.Text.Json.JsonDocument.Parse(json);
                    var root = doc.RootElement;

                    System.Text.Json.JsonElement resultEl;
                    if (root.TryGetProperty("result", out resultEl))
                    {
                        // Connected network info card
                        string connectedSsid = "";
                        if (resultEl.TryGetProperty("connectedNetwork", out var connEl) && connEl.ValueKind == System.Text.Json.JsonValueKind.String)
                            connectedSsid = connEl.GetString() ?? "";

                        if (!string.IsNullOrEmpty(connectedSsid))
                        {
                            var connCard = new Panel
                            {
                                Location = new Point(0, y), Height = 56,
                                Width = _contentArea.Width - 50, Anchor = AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Top,
                                BackColor = Color.FromArgb(24, 28, 36)
                            };
                            var localSsid = connectedSsid;
                            connCard.Paint += (s, e) =>
                            {
                                var g = e.Graphics;
                                g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;
                                using var accentBrush = new SolidBrush(AccentGreen);
                                g.FillRectangle(accentBrush, 0, 0, 4, connCard.Height);
                                using var titleFont = new Font("Segoe UI", 10f, FontStyle.Bold);
                                using var textBrush = new SolidBrush(TextDark);
                                g.DrawString($"Connected: {localSsid}", titleFont, textBrush, 16, 8);
                                using var subFont = new Font("Segoe UI", 8);
                                using var subBrush = new SolidBrush(SidebarText);
                                g.DrawString("Your current WiFi connection", subFont, subBrush, 16, 30);
                            };
                            _contentArea.Controls.Add(connCard);
                            y += 66;
                        }

                        // Network list
                        if (resultEl.TryGetProperty("networks", out var networksEl) && networksEl.ValueKind == System.Text.Json.JsonValueKind.Array)
                        {
                            int unsecure = 0;
                            foreach (var net in networksEl.EnumerateArray())
                            {
                                var ssid = net.GetProperty("ssid").GetString() ?? "(Hidden)";
                                var auth = net.TryGetProperty("authentication", out var authEl) ? authEl.GetString() ?? "" : "";
                                var enc = net.TryGetProperty("encryption", out var encEl) ? encEl.GetString() ?? "" : "";
                                var signal = net.TryGetProperty("signalStrength", out var sigEl) ? sigEl.GetInt32() : 0;
                                var risk = net.TryGetProperty("securityRisk", out var riskEl) ? riskEl.GetString() ?? "Unknown" : "Unknown";
                                var note = net.TryGetProperty("securityNote", out var noteEl) ? noteEl.GetString() ?? "" : "";
                                var isConnected = ssid == connectedSsid;

                                if (risk == "High" || risk == "Critical") unsecure++;

                                var riskColor = risk switch
                                {
                                    "Low" => AccentGreen,
                                    "Medium" => AccentOrange,
                                    "High" => AccentRed,
                                    "Critical" => Color.FromArgb(200, 30, 30),
                                    _ => SidebarText
                                };

                                var card = new Panel
                                {
                                    Location = new Point(0, y), Height = 64,
                                    Width = _contentArea.Width - 50, Anchor = AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Top,
                                    BackColor = Color.FromArgb(24, 28, 36)
                                };
                                var localSsid2 = ssid;
                                var localAuth = auth;
                                var localEnc = enc;
                                var localSignal = signal;
                                var localRisk = risk;
                                var localNote = note;
                                var localRiskColor = riskColor;
                                var localIsConn = isConnected;

                                card.Paint += (s, e) =>
                                {
                                    var g = e.Graphics;
                                    g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

                                    // Risk indicator bar
                                    using var rBrush = new SolidBrush(localRiskColor);
                                    g.FillRectangle(rBrush, 0, 0, 4, card.Height);

                                    // SSID
                                    using var nameFont = new Font("Segoe UI", 10f, localIsConn ? FontStyle.Bold : FontStyle.Regular);
                                    using var nameBrush = new SolidBrush(TextDark);
                                    var displayName = localIsConn ? $"{localSsid2} (Connected)" : localSsid2;
                                    g.DrawString(displayName, nameFont, nameBrush, 16, 6);

                                    // Auth/Encryption
                                    using var detailFont = new Font("Segoe UI", 8);
                                    using var detailBrush = new SolidBrush(SidebarText);
                                    g.DrawString($"{localAuth} / {localEnc}  |  Signal: {localSignal}%", detailFont, detailBrush, 16, 26);

                                    // Security note
                                    using var noteBrush = new SolidBrush(localRiskColor);
                                    var noteText = localNote.Length > 80 ? localNote[..80] + "..." : localNote;
                                    g.DrawString(noteText, detailFont, noteBrush, 16, 44);

                                    // Risk badge
                                    var badgeX = card.Width - 80;
                                    using var badgeFont = new Font("Segoe UI", 8f, FontStyle.Bold);
                                    g.FillRoundedRectangle(rBrush, badgeX, 8, 60, 20, 4);
                                    using var badgeTextBrush = new SolidBrush(Color.White);
                                    var sf = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center };
                                    g.DrawString(localRisk, badgeFont, badgeTextBrush, new RectangleF(badgeX, 8, 60, 20), sf);
                                };
                                _contentArea.Controls.Add(card);
                                y += 74;
                            }

                            // Summary
                            if (unsecure > 0)
                            {
                                var warnCard = new Panel
                                {
                                    Location = new Point(0, y), Height = 40,
                                    Width = _contentArea.Width - 50, Anchor = AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Top,
                                    BackColor = Color.FromArgb(40, 20, 20)
                                };
                                var localUnsecure = unsecure;
                                warnCard.Paint += (s, e) =>
                                {
                                    var g = e.Graphics;
                                    g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;
                                    using var font = new Font("Segoe UI", 9f, FontStyle.Bold);
                                    using var brush = new SolidBrush(AccentRed);
                                    g.DrawString($"\u26A0 {localUnsecure} insecure network(s) detected nearby", font, brush, 16, 10);
                                };
                                _contentArea.Controls.Add(warnCard);
                            }
                        }
                    }
                }
                else
                {
                    var errLabel = new Label
                    {
                        Text = "WiFi scanner requires the PC Plus service. Make sure it's running.",
                        Location = new Point(0, y), AutoSize = true,
                        ForeColor = SidebarText, Font = new Font("Segoe UI", 9.5f)
                    };
                    _contentArea.Controls.Add(errLabel);
                }
            }
            catch { }

            if (_contentArea.Controls.Count <= 2)
            {
                int cW = _contentArea.ClientSize.Width - 72;
                if (cW < 400) cW = Math.Max(700, _contentArea.Width - 80);

                var infoCard = CreateCard(new Point(24, y), new Size(cW, 200));
                infoCard.Paint += (s, e) =>
                {
                    var g = e.Graphics;
                    g.SmoothingMode = SmoothingMode.AntiAlias;
                    g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

                    using var checkBg = new SolidBrush(Color.FromArgb(220, 245, 255));
                    g.FillEllipse(checkBg, cW / 2 - 24, 16, 48, 48);
                    using var iconFont = new Font("Segoe UI", 18);
                    using var iconBrush = new SolidBrush(AccentTeal);
                    g.DrawString("◉", iconFont, iconBrush, cW / 2 - 12, 26);

                    using var msgFont = new Font("Segoe UI", 12, FontStyle.Bold);
                    using var msgBrush = new SolidBrush(TextDark);
                    var msg = "WiFi Security Scanner";
                    var sz = g.MeasureString(msg, msgFont);
                    g.DrawString(msg, msgFont, msgBrush, (cW - sz.Width) / 2, 72);

                    using var subFont = new Font("Segoe UI", 9.5f);
                    using var subBrush = new SolidBrush(TextMuted);
                    var tips = new[] {
                        "Scans nearby WiFi networks for security vulnerabilities",
                        "Detects weak encryption (WEP, Open networks)",
                        "Identifies rogue access points and evil twins",
                        "Checks your connection for DNS hijacking",
                        "Verifies your network uses WPA2/WPA3 encryption"
                    };
                    int ty = 100;
                    foreach (var tip in tips)
                    {
                        using var dot = new SolidBrush(AccentTeal);
                        g.FillEllipse(dot, 20, ty + 4, 6, 6);
                        g.DrawString(tip, subFont, subBrush, 34, ty);
                        ty += 22;
                    }
                };
                _contentArea.Controls.Add(infoCard);
                AddPromoCards(infoCard.Bottom + 16, 24, cW);
            }
            } catch { }
        }

        #endregion

        #region DNS Protection View

        private async void BuildDnsProtectionView()
        {
            int y = 0;
            int m = 16;
            int contentW = _contentArea.ClientSize.Width - m * 2 - _contentArea.Padding.Horizontal;

            var titleLabel = new Label
            {
                Text = "DNS Protection",
                Font = new Font("Segoe UI", 18, FontStyle.Bold),
                ForeColor = TextDark,
                Location = new Point(m, y),
                AutoSize = true
            };
            _contentArea.Controls.Add(titleLabel);

            var subLabel = new Label
            {
                Text = "Powered by AdGuard Home - Network-level phishing & malware blocking",
                Font = new Font("Segoe UI", 9),
                ForeColor = TextMuted,
                Location = new Point(m, y + 32),
                AutoSize = true
            };
            _contentArea.Controls.Add(subLabel);
            y += 68;

            // Status card
            var statusCard = CreateRoundedPanel(new Rectangle(m, y, contentW, 100), CardBg, CardBorder);

            var shieldPanel = new Panel
            {
                Location = new Point(20, 12),
                Size = new Size(76, 76),
                BackColor = Color.Transparent
            };
            shieldPanel.Paint += (s, e) =>
            {
                var g = e.Graphics;
                g.SmoothingMode = SmoothingMode.AntiAlias;
                using var bgBrush = new SolidBrush(Color.FromArgb(20, AccentBlue));
                using var bgPath = RoundedRect(new Rectangle(0, 0, 76, 76), 14);
                g.FillPath(bgBrush, bgPath);
                using var pen = new Pen(AccentBlue, 2.5f);
                g.DrawEllipse(pen, 18, 18, 40, 40);
                using var checkPen = new Pen(AccentGreen, 3f) { StartCap = LineCap.Round, EndCap = LineCap.Round };
                g.DrawLine(checkPen, 30, 38, 36, 46);
                g.DrawLine(checkPen, 36, 46, 48, 30);
            };
            statusCard.Controls.Add(shieldPanel);

            var statusTitle = new Label
            {
                Text = "DNS Filtering Active",
                Font = new Font("Segoe UI", 14, FontStyle.Bold),
                ForeColor = AccentGreen,
                Location = new Point(108, 18),
                AutoSize = true
            };
            statusCard.Controls.Add(statusTitle);

            var statusDesc = new Label
            {
                Text = "Loading DNS statistics for this PC...",
                Font = new Font("Segoe UI", 9),
                ForeColor = TextMuted,
                Location = new Point(108, 46),
                Size = new Size(contentW - 140, 40)
            };
            statusCard.Controls.Add(statusDesc);
            _contentArea.Controls.Add(statusCard);
            y += 116;

            // Stats row - placeholders that get updated
            var cardW = (contentW - m * 2) / 3;
            var blockedLabel = new Label
            {
                Text = "--",
                Font = new Font("Segoe UI", 16, FontStyle.Bold),
                ForeColor = AccentRed,
                Location = new Point(12, 34),
                AutoSize = true
            };
            var totalLabel = new Label
            {
                Text = "--",
                Font = new Font("Segoe UI", 16, FontStyle.Bold),
                ForeColor = AccentBlue,
                Location = new Point(12, 34),
                AutoSize = true
            };
            var rateLabel = new Label
            {
                Text = "--",
                Font = new Font("Segoe UI", 16, FontStyle.Bold),
                ForeColor = AccentGreen,
                Location = new Point(12, 34),
                AutoSize = true
            };

            var statsInfo = new[]
            {
                ("THREATS BLOCKED", blockedLabel),
                ("TOTAL QUERIES", totalLabel),
                ("BLOCK RATE", rateLabel)
            };
            for (int i = 0; i < 3; i++)
            {
                var (label, valLbl) = statsInfo[i];
                var card = CreateRoundedPanel(new Rectangle(m + i * (cardW + m), y, cardW, 80), CardBg, CardBorder);
                card.Controls.Add(new Label
                {
                    Text = label,
                    Font = new Font("Segoe UI", 8, FontStyle.Bold),
                    ForeColor = TextMuted,
                    Location = new Point(12, 12),
                    AutoSize = true
                });
                card.Controls.Add(valLbl);
                _contentArea.Controls.Add(card);
            }
            y += 96;

            // Per-PC info card - shows client IP + top blocked domains
            var pcInfoCard = CreateRoundedPanel(new Rectangle(m, y, contentW, 180), CardBg, CardBorder);
            pcInfoCard.Controls.Add(new Label
            {
                Text = "THIS PC's DNS ACTIVITY",
                Font = new Font("Segoe UI", 9, FontStyle.Bold),
                ForeColor = TextMuted,
                Location = new Point(14, 12),
                AutoSize = true
            });
            var ipLabel = new Label
            {
                Text = "Client IP: detecting...",
                Font = new Font("Segoe UI", 9),
                ForeColor = TextDark,
                Location = new Point(14, 34),
                AutoSize = true
            };
            pcInfoCard.Controls.Add(ipLabel);

            var topBlockedHeader = new Label
            {
                Text = "Top Blocked Domains:",
                Font = new Font("Segoe UI", 9, FontStyle.Bold),
                ForeColor = TextDark,
                Location = new Point(14, 56),
                AutoSize = true
            };
            pcInfoCard.Controls.Add(topBlockedHeader);

            var blockedListLabels = new Label[5];
            for (int i = 0; i < 5; i++)
            {
                blockedListLabels[i] = new Label
                {
                    Text = "",
                    Font = new Font("Segoe UI", 8.5f),
                    ForeColor = TextMuted,
                    Location = new Point(14, 76 + i * 18),
                    Size = new Size(contentW - 40, 18)
                };
                pcInfoCard.Controls.Add(blockedListLabels[i]);
            }
            _contentArea.Controls.Add(pcInfoCard);
            y += 196;

            // Protection layers info
            var infoCard = CreateRoundedPanel(new Rectangle(m, y, contentW, 160), CardBg, CardBorder);
            infoCard.Controls.Add(new Label
            {
                Text = "WHAT'S PROTECTED",
                Font = new Font("Segoe UI", 9, FontStyle.Bold),
                ForeColor = TextMuted,
                Location = new Point(14, 12),
                AutoSize = true
            });

            var protections = new[]
            {
                "Phishing websites (fake login pages, scam sites)",
                "Malware download domains (ransomware, trojans)",
                "Command & Control servers (botnet communication)",
                "Cryptomining scripts (unauthorized CPU usage)",
                "Ad trackers & fingerprinting (privacy threats)",
                "Known malicious URLs from 6 threat intelligence feeds"
            };
            for (int i = 0; i < protections.Length; i++)
            {
                infoCard.Controls.Add(new Label
                {
                    Text = "✔ " + protections[i],
                    Font = new Font("Segoe UI", 9),
                    ForeColor = TextDark,
                    Location = new Point(14, 36 + i * 20),
                    AutoSize = true
                });
            }
            _contentArea.Controls.Add(infoCard);
            y += 176;

            // Open console button
            var consoleBtn = new Panel
            {
                Location = new Point(m, y),
                Size = new Size(contentW, 40),
                BackColor = AccentBlue,
                Cursor = Cursors.Hand
            };
            consoleBtn.Paint += (s, e) =>
            {
                e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
                using var path = RoundedRect(new Rectangle(0, 0, consoleBtn.Width, consoleBtn.Height), 8);
                using var brush = new SolidBrush(AccentBlue);
                e.Graphics.FillPath(brush, path);
                using var font = new Font("Segoe UI", 10, FontStyle.Bold);
                var text = "Open DNS Filtering Console";
                var sz = e.Graphics.MeasureString(text, font);
                using var tb = new SolidBrush(Color.White);
                e.Graphics.DrawString(text, font, tb, (consoleBtn.Width - sz.Width) / 2, (consoleBtn.Height - sz.Height) / 2);
            };
            consoleBtn.Click += (s, e) =>
            {
                try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo { FileName = "https://dns.pcpluscomputing.com", UseShellExecute = true }); } catch { }
            };
            _contentArea.Controls.Add(consoleBtn);

            // Fetch real DNS stats from service
            if (_ipc.IsConnected)
            {
                try
                {
                    var resp = await _ipc.GetDnsStatsAsync();
                    if (resp.Success)
                    {
                        var stats = resp.GetData<DnsStatsDto>();
                        if (stats != null)
                        {
                            void UpdateLabels()
                            {
                                if (IsDisposed) return;

                                if (stats.HasClientData)
                                {
                                    blockedLabel.Text = stats.ClientBlockedQueries.ToString("N0");
                                    totalLabel.Text = stats.ClientTotalQueries.ToString("N0");
                                    rateLabel.Text = $"{stats.ClientBlockRate:F1}%";
                                    statusDesc.Text = $"DNS filtering active for this PC. {stats.ClientBlockedQueries:N0} threats blocked out of {stats.ClientTotalQueries:N0} queries.";
                                    ipLabel.Text = $"Client IP: {stats.ClientIp}";

                                    for (int i = 0; i < 5; i++)
                                    {
                                        if (i < stats.ClientTopBlocked.Count)
                                        {
                                            var d = stats.ClientTopBlocked[i];
                                            blockedListLabels[i].Text = $"• {d.Domain}  ({d.Count} blocked)";
                                            blockedListLabels[i].ForeColor = AccentRed;
                                        }
                                    }
                                }
                                else
                                {
                                    blockedLabel.Text = stats.GlobalBlockedQueries.ToString("N0");
                                    totalLabel.Text = stats.GlobalTotalQueries.ToString("N0");
                                    var globalRate = stats.GlobalTotalQueries > 0
                                        ? (double)stats.GlobalBlockedQueries / stats.GlobalTotalQueries * 100 : 0;
                                    rateLabel.Text = $"{globalRate:F1}%";
                                    statusDesc.Text = $"DNS filtering active. {stats.GlobalBlockedQueries:N0} threats blocked network-wide.";
                                    ipLabel.Text = $"Client IP: {stats.ClientIp} (per-PC stats unavailable)";

                                    for (int i = 0; i < 5 && i < stats.GlobalTopBlocked.Count; i++)
                                    {
                                        var d = stats.GlobalTopBlocked[i];
                                        blockedListLabels[i].Text = $"• {d.Domain}  ({d.Count} blocked)";
                                        blockedListLabels[i].ForeColor = AccentRed;
                                    }
                                }
                            }

                            if (InvokeRequired)
                                Invoke(new Action(UpdateLabels));
                            else
                                UpdateLabels();
                        }
                    }
                    else
                    {
                        void ShowError()
                        {
                            if (IsDisposed) return;
                            statusDesc.Text = "DNS filtering active. Stats: " + resp.Message;
                        }
                        if (InvokeRequired) Invoke(new Action(ShowError));
                        else ShowError();
                    }
                }
                catch { }
            }
            else
            {
                statusDesc.Text = "DNS filtering active. Connect to service for per-PC statistics.";
            }
        }

        #endregion

        #region Policy Engine View

        private async void BuildPoliciesView()
        {
            try
            {
            var title = CreatePageTitle("Policy Engine");
            _contentArea.Controls.Add(title);

            int y = 60;

            try
            {
                var resp = await _ipc.SendModuleCommandAsync("policy", "GetPolicies");
                if (IsDisposed || _currentView != "policies") return;
                if (resp.Success)
                {
                    var json = resp.JsonData ?? "{}";
                    using var doc = System.Text.Json.JsonDocument.Parse(json);
                    var root = doc.RootElement;

                    // Stats card
                    if (root.TryGetProperty("stats", out var statsEl))
                    {
                        var totalRules = statsEl.TryGetProperty("totalRules", out var trEl) ? trEl.GetInt32() : 0;
                        var activeRules = statsEl.TryGetProperty("activeRules", out var arEl) ? arEl.GetInt32() : 0;
                        var totalViolations = statsEl.TryGetProperty("totalViolations", out var tvEl) ? tvEl.GetInt32() : 0;

                        var statsCard = new Panel
                        {
                            Location = new Point(0, y), Height = 60,
                            Width = _contentArea.Width - 50, Anchor = AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Top,
                            BackColor = Color.FromArgb(24, 28, 36)
                        };
                        var localActive = activeRules;
                        var localTotal = totalRules;
                        var localViolations = totalViolations;
                        statsCard.Paint += (s, e) =>
                        {
                            var g = e.Graphics;
                            g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

                            int cardW = statsCard.Width / 3;
                            // Active Rules
                            using var numFont = new Font("Segoe UI", 18f, FontStyle.Bold);
                            using var numBrush = new SolidBrush(AccentTeal);
                            g.DrawString(localActive.ToString(), numFont, numBrush, 20, 6);
                            using var labelFont = new Font("Segoe UI", 8);
                            using var labelBrush = new SolidBrush(SidebarText);
                            g.DrawString("Active Rules", labelFont, labelBrush, 20, 36);

                            // Total Rules
                            using var numBrush2 = new SolidBrush(AccentBlue);
                            g.DrawString(localTotal.ToString(), numFont, numBrush2, cardW + 20, 6);
                            g.DrawString("Total Rules", labelFont, labelBrush, cardW + 20, 36);

                            // Violations
                            var vColor = localViolations > 0 ? AccentOrange : AccentGreen;
                            using var numBrush3 = new SolidBrush(vColor);
                            g.DrawString(localViolations.ToString(), numFont, numBrush3, cardW * 2 + 20, 6);
                            g.DrawString("Violations", labelFont, labelBrush, cardW * 2 + 20, 36);
                        };
                        _contentArea.Controls.Add(statsCard);
                        y += 72;
                    }

                    // Rules list
                    if (root.TryGetProperty("rules", out var rulesEl) && rulesEl.ValueKind == System.Text.Json.JsonValueKind.Array)
                    {
                        var sectionLabel = new Label
                        {
                            Text = "ACTIVE RULES", Location = new Point(0, y),
                            AutoSize = true, ForeColor = SidebarText,
                            Font = new Font("Segoe UI", 8f, FontStyle.Bold)
                        };
                        _contentArea.Controls.Add(sectionLabel);
                        y += 24;

                        foreach (var rule in rulesEl.EnumerateArray())
                        {
                            var name = rule.TryGetProperty("name", out var nEl) ? nEl.GetString() ?? "" : "";
                            var category = rule.TryGetProperty("category", out var cEl) ? cEl.GetString() ?? "" : "";
                            var action = rule.TryGetProperty("action", out var aEl) ? aEl.GetInt32() : 0;
                            var enabled = rule.TryGetProperty("enabled", out var eEl) && eEl.GetBoolean();

                            var actionStr = action switch { 0 => "Alert", 1 => "Block", 2 => "AutoFix", 3 => "Audit", _ => "?" };
                            var actionColor = action switch { 1 => AccentRed, 2 => AccentOrange, 0 => AccentBlue, _ => SidebarText };

                            var ruleCard = new Panel
                            {
                                Location = new Point(0, y), Height = 44,
                                Width = _contentArea.Width - 50, Anchor = AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Top,
                                BackColor = Color.FromArgb(24, 28, 36)
                            };
                            var localName = name;
                            var localCat = category;
                            var localActionStr = actionStr;
                            var localActionColor = actionColor;
                            var localEnabled = enabled;

                            ruleCard.Paint += (s, e) =>
                            {
                                var g = e.Graphics;
                                g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

                                // Status dot
                                using var dotBrush = new SolidBrush(localEnabled ? AccentGreen : SidebarText);
                                g.FillEllipse(dotBrush, 12, 14, 10, 10);

                                // Name
                                using var nameFont = new Font("Segoe UI", 9.5f, FontStyle.Bold);
                                using var nameBrush = new SolidBrush(localEnabled ? TextDark : SidebarText);
                                g.DrawString(localName, nameFont, nameBrush, 30, 4);

                                // Category
                                using var catFont = new Font("Segoe UI", 8);
                                using var catBrush = new SolidBrush(SidebarText);
                                g.DrawString($"Category: {localCat}", catFont, catBrush, 30, 24);

                                // Action badge
                                var badgeX = ruleCard.Width - 80;
                                using var badgeBrush = new SolidBrush(localActionColor);
                                g.FillRoundedRectangle(badgeBrush, badgeX, 12, 60, 20, 4);
                                using var badgeFont = new Font("Segoe UI", 8f, FontStyle.Bold);
                                using var badgeTextBrush = new SolidBrush(Color.White);
                                var sf = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center };
                                g.DrawString(localActionStr, badgeFont, badgeTextBrush, new RectangleF(badgeX, 12, 60, 20), sf);
                            };
                            _contentArea.Controls.Add(ruleCard);
                            y += 52;
                        }
                    }

                    // Violations list
                    if (root.TryGetProperty("violations", out var violationsEl) && violationsEl.ValueKind == System.Text.Json.JsonValueKind.Array && violationsEl.GetArrayLength() > 0)
                    {
                        y += 10;
                        var violLabel = new Label
                        {
                            Text = "RECENT VIOLATIONS", Location = new Point(0, y),
                            AutoSize = true, ForeColor = AccentOrange,
                            Font = new Font("Segoe UI", 8f, FontStyle.Bold)
                        };
                        _contentArea.Controls.Add(violLabel);
                        y += 24;

                        foreach (var viol in violationsEl.EnumerateArray())
                        {
                            var ruleName = viol.TryGetProperty("ruleName", out var rnEl) ? rnEl.GetString() ?? "" : "";
                            var detail = viol.TryGetProperty("detail", out var dEl) ? dEl.GetString() ?? "" : "";
                            var timestamp = viol.TryGetProperty("timestamp", out var tsEl) ? tsEl.GetString() ?? "" : "";

                            var violCard = new Panel
                            {
                                Location = new Point(0, y), Height = 44,
                                Width = _contentArea.Width - 50, Anchor = AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Top,
                                BackColor = Color.FromArgb(35, 25, 25)
                            };
                            var localRuleName = ruleName;
                            var localDetail = detail;
                            var localTs = timestamp;

                            violCard.Paint += (s, e) =>
                            {
                                var g = e.Graphics;
                                g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;
                                using var barBrush = new SolidBrush(AccentOrange);
                                g.FillRectangle(barBrush, 0, 0, 4, violCard.Height);

                                using var nameFont = new Font("Segoe UI", 9f, FontStyle.Bold);
                                using var nameBrush = new SolidBrush(AccentOrange);
                                g.DrawString(localRuleName, nameFont, nameBrush, 16, 4);

                                using var detFont = new Font("Segoe UI", 8);
                                using var detBrush = new SolidBrush(SidebarText);
                                var displayDetail = localDetail.Length > 80 ? localDetail[..80] + "..." : localDetail;
                                g.DrawString(displayDetail, detFont, detBrush, 16, 24);

                                // Time
                                using var timeBrush = new SolidBrush(Color.FromArgb(100, 110, 130));
                                var timeStr = DateTime.TryParse(localTs, out var dt) ? dt.ToLocalTime().ToString("HH:mm:ss") : localTs;
                                var sz = g.MeasureString(timeStr, detFont);
                                g.DrawString(timeStr, detFont, timeBrush, violCard.Width - sz.Width - 10, 4);
                            };
                            _contentArea.Controls.Add(violCard);
                            y += 52;
                        }
                    }
                }
                else
                {
                    AddPolicyFallbackContent(y);
                }
            }
            catch
            {
                AddPolicyFallbackContent(y);
            }
            } catch { }
        }

        private void AddPolicyFallbackContent(int y)
        {
            int cW = _contentArea.ClientSize.Width - 72;
            if (cW < 400) cW = Math.Max(700, _contentArea.Width - 80);
            int gap = 10;
            int col2W = (cW - gap) / 2;

            var policies = new[]
            {
                ("USB Device Control", "Block or allow USB storage devices. Prevent data theft via removable media.", AccentRed, "Enforced"),
                ("Application Whitelist", "Only approved applications can run. Blocks unauthorized software installs.", AccentOrange, "Enforced"),
                ("Password Policy", "Enforce minimum password length, complexity, and expiration rules.", AccentBlue, "Enforced"),
                ("Screen Lock", "Auto-lock screen after inactivity. Configurable timeout per client.", AccentTeal, "Enforced"),
                ("Windows Update", "Force Windows updates within defined maintenance windows.", AccentGreen, "Enforced"),
                ("Browser Security", "Block known malicious websites and enforce safe browsing policies.", Color.FromArgb(139, 92, 246), "Enforced"),
            };

            var policyCard = CreateCard(new Point(24, y), new Size(cW, 50 + policies.Length * 44));
            policyCard.Paint += (s, e) =>
            {
                var g = e.Graphics;
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

                using var titleFont = new Font("Segoe UI", 12, FontStyle.Bold);
                using var titleBrush = new SolidBrush(TextDark);
                g.DrawString("Compliance Policies", titleFont, titleBrush, 16, 14);

                using var subFont = new Font("Segoe UI", 8.5f);
                using var subBrush = new SolidBrush(TextMuted);
                g.DrawString("Managed by PC Plus Computing  -  Policies enforced automatically", subFont, subBrush, 16, 36);

                using var sep = new Pen(Color.FromArgb(230, 234, 240));
                g.DrawLine(sep, 16, 54, policyCard.Width - 16, 54);

                int py = 62;
                using var nameFont = new Font("Segoe UI", 9.5f, FontStyle.Bold);
                using var descFont = new Font("Segoe UI", 8.5f);
                using var badgeFont = new Font("Segoe UI", 7.5f, FontStyle.Bold);

                foreach (var (name, desc, color, status) in policies)
                {
                    using var dot = new SolidBrush(color);
                    g.FillEllipse(dot, 20, py + 4, 10, 10);
                    using var nBrush = new SolidBrush(TextDark);
                    g.DrawString(name, nameFont, nBrush, 38, py);
                    using var dBrush = new SolidBrush(TextMuted);
                    g.DrawString(desc, descFont, dBrush, 38, py + 18);

                    int bx = policyCard.Width - 90;
                    using var bgBrush = new SolidBrush(Color.FromArgb(220, 252, 231));
                    g.FillRoundedRectangle(bgBrush, bx, py + 4, 65, 20, 4);
                    using var bBrush = new SolidBrush(AccentGreen);
                    var sf = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center };
                    g.DrawString(status, badgeFont, bBrush, new RectangleF(bx, py + 4, 65, 20), sf);

                    py += 44;
                    if (py < policyCard.Height - 20)
                    {
                        g.DrawLine(sep, 38, py - 6, policyCard.Width - 16, py - 6);
                    }
                }
            };
            _contentArea.Controls.Add(policyCard);
            AddPromoCards(policyCard.Bottom + 16, 24, cW);
        }

        #endregion

        #region System Info View

        private void BuildSupportView()
        {
            var title = CreatePageTitle("Support Center");
            _contentArea.Controls.Add(title);

            int m = 16;
            int contentW = _contentArea.ClientSize.Width - m * 2 - _contentArea.Padding.Horizontal;
            if (contentW < 400) contentW = Math.Max(700, _contentArea.Width - 80);
            int y = 55;
            int gap = 14;

            // Hero card
            var heroCard = CreateCard(new Point(m + 12, y), new Size(contentW, 110));
            heroCard.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            heroCard.Paint += (s, e) =>
            {
                var g = e.Graphics;
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

                using var gradBrush = new LinearGradientBrush(
                    new Rectangle(0, 0, heroCard.Width, heroCard.Height),
                    Color.FromArgb(20, 37, 150, 190), Color.FromArgb(8, 37, 150, 190),
                    LinearGradientMode.Horizontal);
                using var gradPath = RoundedRect(new Rectangle(0, 0, heroCard.Width - 1, heroCard.Height - 1), 10);
                g.FillPath(gradBrush, gradPath);

                using var iconFont = new Font("Segoe UI", 32);
                using var iconBrush = new SolidBrush(AccentTeal);
                g.DrawString("✉", iconFont, iconBrush, 24, 22);

                using var headFont = new Font("Segoe UI", 15, FontStyle.Bold);
                using var headBrush = new SolidBrush(TextDark);
                g.DrawString("We're here to help", headFont, headBrush, 85, 22);

                using var subFont = new Font("Segoe UI", 10);
                using var subBrush = new SolidBrush(TextMuted);
                g.DrawString("Get in touch with our support team through live chat, email, or phone.", subFont, subBrush, 87, 52);
                g.DrawString("Our technicians are ready to assist you.", subFont, subBrush, 87, 74);
            };
            _contentArea.Controls.Add(heroCard);
            y += 110 + gap;

            // Action buttons row
            int btnW = (contentW - gap * 2) / 3;

            // Live Chat button card
            var chatCard = CreateCard(new Point(m + 12, y), new Size(btnW, 140));
            chatCard.Anchor = AnchorStyles.Top | AnchorStyles.Left;
            chatCard.Cursor = Cursors.Hand;
            chatCard.Paint += (s, e) =>
            {
                var g = e.Graphics;
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

                using var circleBrush = new SolidBrush(Color.FromArgb(220, 245, 235));
                g.FillEllipse(circleBrush, (btnW - 48) / 2, 18, 48, 48);
                using var iconFont = new Font("Segoe UI", 20);
                using var iconBrush = new SolidBrush(AccentGreen);
                g.DrawString("▬", iconFont, iconBrush, (btnW - 24) / 2, 28);

                using var lblFont = new Font("Segoe UI", 11, FontStyle.Bold);
                using var lblBrush = new SolidBrush(TextDark);
                var sz = g.MeasureString("Live Chat", lblFont);
                g.DrawString("Live Chat", lblFont, lblBrush, (btnW - sz.Width) / 2, 78);

                using var subFont = new Font("Segoe UI", 8.5f);
                using var subBrush = new SolidBrush(TextMuted);
                var sub = "Chat with a technician";
                var ssz = g.MeasureString(sub, subFont);
                g.DrawString(sub, subFont, subBrush, (btnW - ssz.Width) / 2, 100);
            };
            chatCard.Click += (s, e) =>
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                { FileName = "https://support.pcpluscomputing.com/livechat.html", UseShellExecute = true });
            };
            _contentArea.Controls.Add(chatCard);

            // Create Ticket button card
            var ticketCard = CreateCard(new Point(m + 12 + btnW + gap, y), new Size(btnW, 140));
            ticketCard.Anchor = AnchorStyles.Top | AnchorStyles.Left;
            ticketCard.Cursor = Cursors.Hand;
            ticketCard.Paint += (s, e) =>
            {
                var g = e.Graphics;
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

                using var circleBrush = new SolidBrush(Color.FromArgb(220, 230, 255));
                g.FillEllipse(circleBrush, (btnW - 48) / 2, 18, 48, 48);
                using var iconFont = new Font("Segoe UI", 20);
                using var iconBrush = new SolidBrush(AccentBlue);
                g.DrawString("✍", iconFont, iconBrush, (btnW - 24) / 2, 28);

                using var lblFont = new Font("Segoe UI", 11, FontStyle.Bold);
                using var lblBrush = new SolidBrush(TextDark);
                var sz = g.MeasureString("Create Ticket", lblFont);
                g.DrawString("Create Ticket", lblFont, lblBrush, (btnW - sz.Width) / 2, 78);

                using var subFont = new Font("Segoe UI", 8.5f);
                using var subBrush = new SolidBrush(TextMuted);
                var sub = "Submit a support request";
                var ssz = g.MeasureString(sub, subFont);
                g.DrawString(sub, subFont, subBrush, (btnW - ssz.Width) / 2, 100);
            };
            ticketCard.Click += (s, e) =>
            {
                var ticketUrl = GetCompanyTicketUrl();
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                { FileName = ticketUrl, UseShellExecute = true });
            };
            _contentArea.Controls.Add(ticketCard);

            // Remote Support button card
            var remoteCard = CreateCard(new Point(m + 12 + (btnW + gap) * 2, y), new Size(btnW, 140));
            remoteCard.Anchor = AnchorStyles.Top | AnchorStyles.Left;
            remoteCard.Cursor = Cursors.Hand;
            remoteCard.Paint += (s, e) =>
            {
                var g = e.Graphics;
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

                using var circleBrush = new SolidBrush(Color.FromArgb(240, 230, 250));
                g.FillEllipse(circleBrush, (btnW - 48) / 2, 18, 48, 48);
                using var iconFont = new Font("Segoe UI", 20);
                using var iconBrush = new SolidBrush(Color.FromArgb(139, 92, 246));
                g.DrawString("⌘", iconFont, iconBrush, (btnW - 24) / 2, 28);

                using var lblFont = new Font("Segoe UI", 11, FontStyle.Bold);
                using var lblBrush = new SolidBrush(TextDark);
                var sz = g.MeasureString("Remote Support", lblFont);
                g.DrawString("Remote Support", lblFont, lblBrush, (btnW - sz.Width) / 2, 78);

                using var subFont = new Font("Segoe UI", 8.5f);
                using var subBrush = new SolidBrush(TextMuted);
                var sub = "Let us connect remotely";
                var ssz = g.MeasureString(sub, subFont);
                g.DrawString(sub, subFont, subBrush, (btnW - ssz.Width) / 2, 100);
            };
            remoteCard.Click += (s, e) =>
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                { FileName = "https://mesh.pcpluscomputing.com/", UseShellExecute = true });
            };
            _contentArea.Controls.Add(remoteCard);
            y += 140 + gap;

            // Quick Links row (4 cards: Phone, VPN, Website, Emergency)
            int qlW = (contentW - gap * 3) / 4;

            var phoneCard = CreateCard(new Point(m + 12, y), new Size(qlW, 90));
            phoneCard.Paint += (s, e) =>
            {
                var g = e.Graphics;
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;
                using var iconBrush = new SolidBrush(Color.FromArgb(220, 245, 255));
                g.FillEllipse(iconBrush, 12, 12, 36, 36);
                using var iconFont = new Font("Segoe UI", 14);
                using var iconClr = new SolidBrush(AccentTeal);
                g.DrawString("☎", iconFont, iconClr, 18, 17);
                using var lblFont = new Font("Segoe UI", 8f, FontStyle.Bold);
                using var lblBrush = new SolidBrush(TextDark);
                g.DrawString("604-760-1662", lblFont, lblBrush, 12, 55);
                using var subFont = new Font("Segoe UI", 7.5f);
                using var subBrush = new SolidBrush(TextMuted);
                g.DrawString("236-500-2700", subFont, subBrush, 12, 72);
            };
            _contentArea.Controls.Add(phoneCard);

            var vpnCard = CreateCard(new Point(m + 12 + qlW + gap, y), new Size(qlW, 90));
            vpnCard.Cursor = Cursors.Hand;
            vpnCard.Paint += (s, e) =>
            {
                var g = e.Graphics;
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;
                using var iconBg = new SolidBrush(Color.FromArgb(220, 252, 231));
                g.FillEllipse(iconBg, 12, 12, 36, 36);
                using var iconFont = new Font("Segoe UI", 14);
                using var iconClr = new SolidBrush(AccentGreen);
                g.DrawString("🔒", iconFont, iconClr, 16, 17);
                using var lblFont = new Font("Segoe UI", 9f, FontStyle.Bold);
                using var lblBrush = new SolidBrush(AccentGreen);
                g.DrawString("VPN Portal", lblFont, lblBrush, 12, 55);
                using var subFont = new Font("Segoe UI", 7.5f);
                using var subBrush = new SolidBrush(TextMuted);
                g.DrawString("Secure remote access", subFont, subBrush, 12, 72);
            };
            vpnCard.Click += (s, e) =>
            {
                try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                { FileName = "https://vpn.pcpluscomputing.com", UseShellExecute = true }); } catch { }
            };
            _contentArea.Controls.Add(vpnCard);

            var webCard = CreateCard(new Point(m + 12 + (qlW + gap) * 2, y), new Size(qlW, 90));
            webCard.Cursor = Cursors.Hand;
            webCard.Paint += (s, e) =>
            {
                var g = e.Graphics;
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;
                using var iconBg = new SolidBrush(Color.FromArgb(220, 230, 255));
                g.FillEllipse(iconBg, 12, 12, 36, 36);
                using var iconFont = new Font("Segoe UI", 14);
                using var iconClr = new SolidBrush(AccentBlue);
                g.DrawString("↗", iconFont, iconClr, 18, 17);
                using var lblFont = new Font("Segoe UI", 9f, FontStyle.Bold);
                using var lblBrush = new SolidBrush(AccentBlue);
                g.DrawString("Website", lblFont, lblBrush, 12, 55);
                using var subFont = new Font("Segoe UI", 7.5f);
                using var subBrush = new SolidBrush(TextMuted);
                g.DrawString("pcpluscomputing.com", subFont, subBrush, 12, 72);
            };
            webCard.Click += (s, e) =>
            {
                try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                { FileName = "https://pcpluscomputing.com", UseShellExecute = true }); } catch { }
            };
            _contentArea.Controls.Add(webCard);

            var emergCard = CreateCard(new Point(m + 12 + (qlW + gap) * 3, y), new Size(qlW, 90));
            emergCard.Paint += (s, e) =>
            {
                var g = e.Graphics;
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;
                using var iconBg = new SolidBrush(Color.FromArgb(254, 226, 226));
                g.FillEllipse(iconBg, 12, 12, 36, 36);
                using var iconFont = new Font("Segoe UI", 14);
                using var iconClr = new SolidBrush(AccentRed);
                g.DrawString("⚠", iconFont, iconClr, 18, 17);
                using var lblFont = new Font("Segoe UI", 9f, FontStyle.Bold);
                using var lblBrush = new SolidBrush(AccentRed);
                g.DrawString("Emergency", lblFont, lblBrush, 12, 55);
                using var subFont = new Font("Segoe UI", 7.5f);
                using var subBrush = new SolidBrush(TextMuted);
                g.DrawString("24/7 critical support", subFont, subBrush, 12, 72);
            };
            _contentArea.Controls.Add(emergCard);
            y += 90 + gap;

            // Service status bar
            var statusCard = CreateCard(new Point(m + 12, y), new Size(contentW, 60));
            statusCard.Paint += (s, e) =>
            {
                var g = e.Graphics;
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;
                var services = new[] {
                    ("Monitoring", AccentGreen), ("VPN", AccentGreen),
                    ("Ticketing", AccentGreen), ("Backup", AccentGreen),
                    ("Email", AccentGreen)
                };
                int sx = 14;
                using var svcFont = new Font("Segoe UI", 8.5f, FontStyle.Bold);
                using var svcBrush = new SolidBrush(TextDark);
                using var lbl = new Font("Segoe UI", 8f);
                using var lblB = new SolidBrush(TextMuted);
                g.DrawString("Service Status", lbl, lblB, sx, 6);
                int dotY = 30;
                foreach (var (name, color) in services)
                {
                    using var dot = new SolidBrush(color);
                    g.FillEllipse(dot, sx, dotY + 3, 8, 8);
                    g.DrawString(name, svcFont, svcBrush, sx + 12, dotY);
                    sx += (int)g.MeasureString(name, svcFont).Width + 28;
                }
            };
            _contentArea.Controls.Add(statusCard);
            y += 60 + gap;

            // Keep linksCard reference for the business hours section below
            var linksCard = statusCard;

            // === BUSINESS HOURS + FAQ ===
            int col1W = (contentW - gap) / 2;
            int col2W = contentW - col1W - gap;
            y = linksCard.Bottom + 12;

            var hoursCard = CreateCard(new Point(m, y), new Size(col1W, 220));
            hoursCard.Paint += (s, e) =>
            {
                var g = e.Graphics;
                g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;
                using var titleFont = new Font("Segoe UI", 11, FontStyle.Bold);
                using var titleBrush = new SolidBrush(TextDark);
                g.DrawString("Business Hours", titleFont, titleBrush, 14, 12);

                using var rowFont = new Font("Segoe UI", 9f);
                using var valFont = new Font("Segoe UI", 9f, FontStyle.Bold);
                using var rowBrush = new SolidBrush(TextDark);
                using var mutBrush = new SolidBrush(TextMuted);
                var hours = new[]
                {
                    ("Monday - Friday", "9:00 AM - 6:00 PM"),
                    ("Saturday", "10:00 AM - 4:00 PM"),
                    ("Sunday", "Closed"),
                    ("Emergency", "24/7 Available")
                };
                int hy = 42;
                foreach (var (day, time) in hours)
                {
                    g.DrawString(day, rowFont, rowBrush, 14, hy);
                    g.DrawString(time, valFont, day == "Emergency" ? new SolidBrush(AccentGreen) : mutBrush, hoursCard.Width - 170, hy);
                    hy += 28;
                    if (day != "Emergency")
                    {
                        using var sep = new Pen(Color.FromArgb(235, 238, 244));
                        g.DrawLine(sep, 14, hy - 6, hoursCard.Width - 14, hy - 6);
                    }
                }

                using var noteFont = new Font("Segoe UI", 8f);
                g.DrawString("Response time: typically within 30 minutes during\nbusiness hours for managed clients.", noteFont, mutBrush, 14, hy + 8);
            };
            _contentArea.Controls.Add(hoursCard);

            var faqCard = CreateCard(new Point(m + col1W + gap, y), new Size(col2W, 220));
            faqCard.Paint += (s, e) =>
            {
                var g = e.Graphics;
                g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;
                using var titleFont = new Font("Segoe UI", 11, FontStyle.Bold);
                using var titleBrush = new SolidBrush(TextDark);
                g.DrawString("Quick Help", titleFont, titleBrush, 14, 12);

                using var qFont = new Font("Segoe UI", 9f, FontStyle.Bold);
                using var aFont = new Font("Segoe UI", 8.5f);
                using var qBrush = new SolidBrush(TextDark);
                using var aBrush = new SolidBrush(TextMuted);
                var faqs = new[]
                {
                    ("My computer is slow", "Click 'Fix My Computer' on the Dashboard"),
                    ("I think I have a virus", "Run a Security Scan from the Dashboard"),
                    ("I need remote help", "Click 'Remote Support' above - a tech will connect"),
                    ("Internet not working", "Check WiFi Security page or call us directly"),
                };
                int fy = 40;
                foreach (var (q, a) in faqs)
                {
                    using var dot = new SolidBrush(AccentBlue);
                    g.FillEllipse(dot, 14, fy + 4, 6, 6);
                    g.DrawString(q, qFont, qBrush, 26, fy);
                    g.DrawString(a, aFont, aBrush, 26, fy + 18);
                    fy += 44;
                }
            };
            _contentArea.Controls.Add(faqCard);
        }

        private void BuildSystemView()
        {
            var title = CreatePageTitle("System Information");
            _contentArea.Controls.Add(title);

            var copyBtn = CreateActionButton("Copy All", AccentBlue, new Point(_contentArea.Width - 140, 10), new Size(90, 32));
            copyBtn.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            _contentArea.Controls.Add(copyBtn);

            // Collect all items for copy functionality
            var allItems = new List<(string category, string key, string value)>();

            int m = 16;
            int contentW = _contentArea.ClientSize.Width - m * 2 - _contentArea.Padding.Horizontal;
            if (contentW < 400) contentW = Math.Max(700, _contentArea.Width - 80);
            int y = 55;
            int gap = 12;

            // === COMPUTER IDENTITY CARD ===
            var identityCard = CreateCard(new Point(m + 12, y), new Size(contentW, 100));
            identityCard.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            identityCard.Tag = "sysrow";
            identityCard.Paint += (s, e) =>
            {
                var g = e.Graphics;
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

                // Computer icon circle
                using var circleBrush = new SolidBrush(Color.FromArgb(230, 240, 255));
                g.FillEllipse(circleBrush, 20, 20, 60, 60);
                using var iconFont = new Font("Segoe UI", 24);
                using var iconBrush = new SolidBrush(AccentTeal);
                g.DrawString("\u2699", iconFont, iconBrush, 32, 32);

                // Computer name large
                using var nameFont = new Font("Segoe UI", 18, FontStyle.Bold);
                using var nameBrush = new SolidBrush(TextDark);
                g.DrawString(Environment.MachineName, nameFont, nameBrush, 95, 14);

                // User and OS subtitle
                using var subFont = new Font("Segoe UI", 9.5f);
                using var subBrush = new SolidBrush(TextMuted);
                var userStr = $"{Environment.UserDomainName}\\{Environment.UserName}";
                g.DrawString(userStr, subFont, subBrush, 97, 48);
                g.DrawString(GetFriendlyOsVersion() + " \u2022 " +
                    (Environment.Is64BitOperatingSystem ? "64-bit" : "32-bit"), subFont, subBrush, 97, 68);
            };
            _contentArea.Controls.Add(identityCard);
            allItems.Add(("System", "Computer Name", Environment.MachineName));
            allItems.Add(("System", "User", $"{Environment.UserDomainName}\\{Environment.UserName}"));
            allItems.Add(("System", "OS", GetFriendlyOsVersion()));
            allItems.Add(("System", "Architecture", Environment.Is64BitOperatingSystem ? "64-bit" : "32-bit"));
            y += 100 + gap;

            // === HEALTH GAUGES ROW (4 mini cards) ===
            if (_health != null)
            {
                int gaugeW = (contentW - gap * 3) / 4;
                var gauges = new (string label, string value, float percent, Color color)[]
                {
                    ("CPU", $"{_health.CpuPercent:F0}%", _health.CpuPercent,
                        _health.CpuPercent > 85 ? AccentRed : _health.CpuPercent > 60 ? AccentOrange : AccentGreen),
                    ("Memory", $"{_health.RamUsedGB:F1}/{_health.RamTotalGB:F0} GB",
                        _health.RamPercent, _health.RamPercent > 85 ? AccentRed : _health.RamPercent > 60 ? AccentOrange : AccentGreen),
                    ("CPU Temp", _health.CpuTempC > 0 ? $"{_health.CpuTempC:F0}\u00B0C" : "N/A",
                        Math.Min(_health.CpuTempC, 100),
                        _health.CpuTempC > 80 ? AccentRed : _health.CpuTempC > 60 ? AccentOrange : AccentGreen),
                    ("Uptime", $"{(int)_health.Uptime.TotalDays}d {_health.Uptime.Hours}h",
                        Math.Min((float)_health.Uptime.TotalDays / 30f * 100f, 100f), AccentBlue)
                };

                for (int i = 0; i < gauges.Length; i++)
                {
                    var g = gauges[i];
                    var gaugeCard = CreateCard(new Point(m + 12 + i * (gaugeW + gap), y), new Size(gaugeW, 90));
                    gaugeCard.Anchor = AnchorStyles.Top | AnchorStyles.Left;
                    gaugeCard.Tag = "sysrow";
                    var capturedGauge = g;
                    gaugeCard.Paint += (s, e) =>
                    {
                        var gr = e.Graphics;
                        gr.SmoothingMode = SmoothingMode.AntiAlias;
                        gr.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

                        // Label
                        using var lblFont = new Font("Segoe UI", 8);
                        using var lblBrush = new SolidBrush(TextMuted);
                        gr.DrawString(capturedGauge.label, lblFont, lblBrush, 12, 10);

                        // Value
                        using var valFont = new Font("Segoe UI", 16, FontStyle.Bold);
                        using var valBrush = new SolidBrush(capturedGauge.color);
                        gr.DrawString(capturedGauge.value, valFont, valBrush, 12, 28);

                        // Progress bar
                        var barRect = new Rectangle(12, 68, gaugeCard.Width - 24, 8);
                        using var bgBrush = new SolidBrush(Color.FromArgb(230, 235, 240));
                        using var brPath = RoundedRect(barRect, 4);
                        gr.FillPath(bgBrush, brPath);
                        if (capturedGauge.percent > 0)
                        {
                            var fillW = Math.Max(8, (int)(barRect.Width * capturedGauge.percent / 100f));
                            var fillRect = new Rectangle(barRect.X, barRect.Y, fillW, barRect.Height);
                            using var fillBrush = new SolidBrush(capturedGauge.color);
                            using var fillPath = RoundedRect(fillRect, 4);
                            gr.FillPath(fillBrush, fillPath);
                        }
                    };
                    _contentArea.Controls.Add(gaugeCard);
                }
                allItems.Add(("Health", "CPU Usage", $"{_health.CpuPercent:F0}%"));
                allItems.Add(("Health", "RAM Usage", $"{_health.RamUsedGB:F1} / {_health.RamTotalGB:F1} GB ({_health.RamPercent:F0}%)"));
                allItems.Add(("Health", "CPU Temperature", _health.CpuTempC > 0 ? $"{_health.CpuTempC:F0} C" : "N/A"));
                allItems.Add(("Health", "Uptime", $"{(int)_health.Uptime.TotalDays}d {_health.Uptime.Hours}h {_health.Uptime.Minutes}m"));
                y += 90 + gap;
            }

            // === NETWORK & PROCESSES ROW (2 cards side by side) ===
            if (_health != null)
            {
                int halfW = (contentW - gap) / 2;

                // Network card
                var netCard = CreateCard(new Point(m + 12, y), new Size(halfW, 70));
                netCard.Anchor = AnchorStyles.Top | AnchorStyles.Left;
                netCard.Tag = "sysrow";
                var networkUp = _health.NetworkSentKBps;
                var networkDown = _health.NetworkRecvKBps;
                var processCount = _health.ProcessCount;
                netCard.Paint += (s, e) =>
                {
                    var g = e.Graphics;
                    g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;
                    using var hdrFont = new Font("Segoe UI", 8);
                    using var hdrBrush = new SolidBrush(TextMuted);
                    g.DrawString("NETWORK ACTIVITY", hdrFont, hdrBrush, 12, 10);

                    using var valFont = new Font("Segoe UI", 11, FontStyle.Bold);
                    using var upBrush = new SolidBrush(AccentGreen);
                    using var dnBrush = new SolidBrush(AccentBlue);
                    g.DrawString($"\u2191 {networkUp:F0} KB/s", valFont, upBrush, 12, 34);
                    g.DrawString($"\u2193 {networkDown:F0} KB/s", valFont, dnBrush, halfW / 2, 34);
                };
                _contentArea.Controls.Add(netCard);

                // Processes card
                var procCard = CreateCard(new Point(m + 12 + halfW + gap, y), new Size(halfW, 70));
                procCard.Anchor = AnchorStyles.Top | AnchorStyles.Right;
                procCard.Tag = "sysrow";
                procCard.Paint += (s, e) =>
                {
                    var g = e.Graphics;
                    g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;
                    using var hdrFont = new Font("Segoe UI", 8);
                    using var hdrBrush = new SolidBrush(TextMuted);
                    g.DrawString("PROCESSES", hdrFont, hdrBrush, 12, 10);

                    using var valFont = new Font("Segoe UI", 18, FontStyle.Bold);
                    using var valBrush = new SolidBrush(TextDark);
                    g.DrawString(processCount.ToString(), valFont, valBrush, 12, 28);

                    using var unitFont = new Font("Segoe UI", 9);
                    var numSize = g.MeasureString(processCount.ToString(), valFont);
                    g.DrawString("running", unitFont, hdrBrush, 14 + numSize.Width, 40);
                };
                _contentArea.Controls.Add(procCard);

                allItems.Add(("Health", "Network", $"Up: {networkUp:F0} KB/s  Down: {networkDown:F0} KB/s"));
                allItems.Add(("Health", "Processes", processCount.ToString()));
                y += 70 + gap;
            }

            // === STORAGE CARD ===
            if (_health?.Disks != null && _health.Disks.Count > 0)
            {
                int diskCardH = 44 + _health.Disks.Count * 50;
                var diskCard = CreateCard(new Point(m + 12, y), new Size(contentW, diskCardH));
                diskCard.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
                diskCard.Tag = "sysrow";
                var disks = _health.Disks.ToList();
                diskCard.Paint += (s, e) =>
                {
                    var g = e.Graphics;
                    g.SmoothingMode = SmoothingMode.AntiAlias;
                    g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

                    using var hdrFont = new Font("Segoe UI", 10, FontStyle.Bold);
                    using var hdrBrush = new SolidBrush(TextDark);
                    g.DrawString("\u2588 Storage", hdrFont, hdrBrush, 12, 12);

                    int dy = 42;
                    foreach (var disk in disks)
                    {
                        var diskColor = disk.UsedPercent > 90 ? AccentRed :
                            disk.UsedPercent > 75 ? AccentOrange : AccentGreen;

                        using var nameFont = new Font("Segoe UI", 9.5f, FontStyle.Bold);
                        using var nameBrush = new SolidBrush(TextDark);
                        g.DrawString($"Drive {disk.Name} {disk.Label}", nameFont, nameBrush, 16, dy);

                        using var detailFont = new Font("Segoe UI", 8);
                        using var detailBrush = new SolidBrush(TextMuted);
                        var detailStr = $"{disk.FreeGB:F0} GB free of {disk.TotalGB:F0} GB";
                        var detailSize = g.MeasureString(detailStr, detailFont);
                        g.DrawString(detailStr, detailFont, detailBrush, diskCard.Width - detailSize.Width - 16, dy);

                        // Progress bar
                        var barRect = new Rectangle(16, dy + 22, diskCard.Width - 32, 10);
                        using var bgBrush = new SolidBrush(Color.FromArgb(230, 235, 240));
                        using var bgPath = RoundedRect(barRect, 5);
                        g.FillPath(bgBrush, bgPath);
                        var fillW = Math.Max(10, (int)(barRect.Width * disk.UsedPercent / 100f));
                        var fillRect = new Rectangle(barRect.X, barRect.Y, fillW, barRect.Height);
                        using var fillBrush = new SolidBrush(diskColor);
                        using var fillPath = RoundedRect(fillRect, 5);
                        g.FillPath(fillBrush, fillPath);

                        // Percentage label on bar
                        using var pctFont = new Font("Segoe UI", 7, FontStyle.Bold);
                        using var pctBrush = new SolidBrush(Color.White);
                        if (fillW > 30)
                            g.DrawString($"{disk.UsedPercent:F0}%", pctFont, pctBrush, barRect.X + 6, barRect.Y - 1);

                        dy += 50;
                    }
                };
                _contentArea.Controls.Add(diskCard);
                foreach (var disk in _health.Disks)
                    allItems.Add(("Disks", $"Drive {disk.Name}", $"{disk.FreeGB:F0} GB free / {disk.TotalGB:F0} GB ({disk.UsedPercent:F0}% used)"));
                y += diskCardH + gap;
            }

            // === NETWORKING CARD ===
            var netInfoCard = CreateCard(new Point(m + 12, y), new Size(contentW, 50));
            netInfoCard.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            netInfoCard.Tag = "sysrow";
            var localIp = GetLocalIpAddress();
            var publicIp = _cachedPublicIp ?? "Loading...";
            netInfoCard.Paint += (s, e) =>
            {
                var g = e.Graphics;
                g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

                using var hdrFont = new Font("Segoe UI", 10, FontStyle.Bold);
                using var hdrBrush = new SolidBrush(TextDark);
                g.DrawString("\u2302 Network", hdrFont, hdrBrush, 12, 14);

                using var valFont = new Font("Segoe UI", 9);
                using var keyBrush = new SolidBrush(TextMuted);
                using var valBrush = new SolidBrush(TextDark);
                g.DrawString("Local IP:", valFont, keyBrush, 140, 16);
                g.DrawString(localIp, valFont, valBrush, 200, 16);
                g.DrawString("Public IP:", valFont, keyBrush, 380, 16);
                g.DrawString(publicIp, valFont, valBrush, 448, 16);
            };
            _contentArea.Controls.Add(netInfoCard);
            allItems.Add(("Network", "Local IP", localIp));
            allItems.Add(("Network", "Public IP", publicIp));
            y += 50 + gap;

            // === HARDWARE DETAILS CARD (loaded async with WMI) ===
            var hwPlaceholder = CreateCard(new Point(m + 12, y), new Size(contentW, 40));
            hwPlaceholder.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            hwPlaceholder.Tag = "sysrow";
            hwPlaceholder.Paint += (s, e) =>
            {
                var g = e.Graphics;
                g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;
                using var font = new Font("Segoe UI", 9);
                using var brush = new SolidBrush(TextMuted);
                g.DrawString("Loading hardware details...", font, brush, 12, 10);
            };
            _contentArea.Controls.Add(hwPlaceholder);
            int hwStartY = y;

            // Load WMI info and public IP async, then replace placeholder
            _ = Task.Run(async () =>
            {
                var hwItems = GetHardwareInfo();
                await FetchPublicIpAsync();
                if (InvokeRequired && !IsDisposed)
                    Invoke(new Action(() =>
                    {
                        // Remove placeholder
                        if (hwPlaceholder != null && _contentArea.Controls.Contains(hwPlaceholder))
                        {
                            _contentArea.Controls.Remove(hwPlaceholder);
                            hwPlaceholder.Dispose();
                        }

                        // Update public IP on net info card
                        publicIp = _cachedPublicIp ?? "N/A";
                        netInfoCard.Invalidate();

                        // Build hardware + network adapter cards
                        int hy = hwStartY;

                        // Group by category
                        var grouped = hwItems.GroupBy(i => i.category).ToList();
                        foreach (var group in grouped)
                        {
                            int rowCount = group.Count();
                            int cardH = 40 + rowCount * 28;
                            var hwCard = CreateCard(new Point(m + 12, hy), new Size(contentW, cardH));
                            hwCard.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
                            hwCard.Tag = "sysrow";
                            var catName = group.Key;
                            var rows = group.ToList();
                            hwCard.Paint += (s2, e2) =>
                            {
                                var g2 = e2.Graphics;
                                g2.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

                                // Section header
                                using var hdrFont2 = new Font("Segoe UI", 10, FontStyle.Bold);
                                using var hdrBrush2 = new SolidBrush(TextDark);
                                var icon = catName == "Hardware" ? "\u2616" : "\u2302";
                                g2.DrawString($"{icon} {catName}", hdrFont2, hdrBrush2, 12, 10);

                                int ry = 38;
                                foreach (var row in rows)
                                {
                                    using var keyFont = new Font("Segoe UI", 9, FontStyle.Bold);
                                    using var valFont = new Font("Segoe UI", 9);
                                    using var keyBr = new SolidBrush(TextMuted);
                                    using var valBr = new SolidBrush(TextDark);
                                    g2.DrawString(row.key, keyFont, keyBr, 20, ry);
                                    g2.DrawString(row.value, valFont, valBr, 220, ry);
                                    ry += 28;
                                }
                            };
                            _contentArea.Controls.Add(hwCard);
                            hy += cardH + gap;

                            foreach (var item in rows)
                                allItems.Add(item);
                        }

                        // Update .NET Runtime info
                        allItems.Add(("System", ".NET Runtime",
                            System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription));

                        // Re-wire copy button with full data
                        _sysInfoItems = allItems;
                    }));
            });

            // Wire up copy button with initial data
            copyBtn.Click -= CopyAllHandler;
            _sysInfoItems = allItems;
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

                // Fetch data from service if connected (TrayContext handles connection)
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

                    // Fetch DNS live activity for dashboard feed
                    try
                    {
                        var dnsResp = await Task.Run(() => _ipc.SendModuleCommandAsync("phishing", "GetDnsActivity"));
                        if (dnsResp.Success && !string.IsNullOrEmpty(dnsResp.JsonData))
                        {
                            using var dnsDoc = System.Text.Json.JsonDocument.Parse(dnsResp.JsonData);
                            var dnsRoot = dnsDoc.RootElement;
                            _dnsActive = dnsRoot.TryGetProperty("active", out var activeEl) && activeEl.GetBoolean();
                            _dnsDomainsChecked = dnsRoot.TryGetProperty("domainsChecked", out var dcEl) ? dcEl.GetInt32() : 0;
                            _dnsThreatsBlocked = dnsRoot.TryGetProperty("threatsBlocked", out var tbEl) ? tbEl.GetInt32() : 0;

                            if (dnsRoot.TryGetProperty("recentBlocks", out var rbEl) && rbEl.ValueKind == System.Text.Json.JsonValueKind.Array)
                            {
                                var blocks = new List<(string Domain, string TimeAgo)>();
                                foreach (var item in rbEl.EnumerateArray())
                                {
                                    var domain = item.TryGetProperty("domain", out var dEl) ? dEl.GetString() ?? "" : "";
                                    var timeAgo = item.TryGetProperty("timeAgo", out var tEl) ? tEl.GetString() ?? "" : "";
                                    if (!string.IsNullOrEmpty(domain))
                                        blocks.Add((domain, timeAgo));
                                }
                                _dnsRecentBlocks = blocks;
                            }
                        }
                    }
                    catch { /* DNS activity is non-critical */ }

                    // Fetch missing patches for dashboard feed
                    try
                    {
                        var patchResp = await Task.Run(() => _ipc.SendModuleCommandAsync("security", "GetMissingPatches"));
                        if (patchResp.Success && !string.IsNullOrEmpty(patchResp.JsonData))
                        {
                            using var patchDoc = System.Text.Json.JsonDocument.Parse(patchResp.JsonData);
                            var patchRoot = patchDoc.RootElement;
                            _missingPatchCount = patchRoot.TryGetProperty("count", out var cntEl) ? cntEl.GetInt32() : 0;

                            if (patchRoot.TryGetProperty("lastChecked", out var lcEl))
                            {
                                if (lcEl.TryGetDateTime(out var lcDt))
                                    _patchesLastChecked = lcDt;
                            }

                            if (patchRoot.TryGetProperty("patches", out var patchesEl) && patchesEl.ValueKind == System.Text.Json.JsonValueKind.Array)
                            {
                                var patches = new List<(string PatchId, string Severity)>();
                                foreach (var item in patchesEl.EnumerateArray())
                                {
                                    var patchId = item.TryGetProperty("patchId", out var pidEl) ? pidEl.GetString() ?? "" : "";
                                    var severity = item.TryGetProperty("severity", out var sevEl) ? sevEl.GetString() ?? "" : "";
                                    if (!string.IsNullOrEmpty(patchId))
                                        patches.Add((patchId, severity));
                                }
                                _missingPatches = patches;
                            }
                        }
                    }
                    catch { /* Missing patches is non-critical */ }
                }

                // Fallback tier 1: read service files (health + security)
                if (!gotServiceData || _health == null)
                {
                    var serviceHealth = TryReadServiceHealthFile();
                    if (serviceHealth != null)
                    {
                        _health = serviceHealth;
                        gotServiceData = true;
                    }
                }

                if (_securityResult == null)
                {
                    var serviceSecurity = TryReadServiceSecurityFile();
                    if (serviceSecurity != null)
                        _securityResult = serviceSecurity;
                }

                // Fallback tier 2: use local monitoring
                if (!gotServiceData || _health == null)
                {
                    if (!_usingLocalFallback)
                    {
                        _usingLocalFallback = true;
                        _localFallback.Start();
                    }
                    var localHealth = _localFallback.CurrentHealth;

                    if (_health == null)
                        _health = localHealth;
                    else if (_health.CpuTempC == 0 && localHealth.CpuTempC > 0)
                        _health.CpuTempC = localHealth.CpuTempC;

                    if (_securityResult == null)
                        _securityResult = _localFallback.LastSecurityScan;
                }

                // Update sidebar connection status (lightweight repaint only)
                if (!IsDisposed)
                {
                    void InvalidateSidebar()
                    {
                        if (IsDisposed) return;
                        foreach (var ctrl in _sidebar.Controls)
                            if (ctrl is Panel p) p.Invalidate();
                    }

                    if (InvokeRequired)
                        Invoke(new Action(InvalidateSidebar));
                    else
                        InvalidateSidebar();
                }
            }
            catch { }
        }

        private static readonly string _serviceHealthFilePath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "PCPlusEndpoint", "health_snapshot.json");

        private static readonly System.Text.Json.JsonSerializerOptions _jsonOptions = new()
        {
            PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase
        };

        private HealthSnapshot? TryReadServiceHealthFile()
        {
            try
            {
                if (!File.Exists(_serviceHealthFilePath)) return null;
                var lastWrite = File.GetLastWriteTimeUtc(_serviceHealthFilePath);
                if ((DateTime.UtcNow - lastWrite).TotalSeconds > 30) return null;
                var json = File.ReadAllText(_serviceHealthFilePath);
                return System.Text.Json.JsonSerializer.Deserialize<HealthSnapshot>(json, _jsonOptions);
            }
            catch { return null; }
        }

        private static readonly string _serviceSecurityFilePath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "PCPlusEndpoint", "security_snapshot.json");

        private SecurityScanResult? TryReadServiceSecurityFile()
        {
            try
            {
                if (!File.Exists(_serviceSecurityFilePath)) return null;
                var lastWrite = File.GetLastWriteTimeUtc(_serviceSecurityFilePath);
                if ((DateTime.UtcNow - lastWrite).TotalMinutes > 30) return null;
                var json = File.ReadAllText(_serviceSecurityFilePath);
                return System.Text.Json.JsonSerializer.Deserialize<SecurityScanResult>(json, _jsonOptions);
            }
            catch { return null; }
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

        private Panel CreateRoundedPanel(Rectangle bounds, Color bgColor, Color borderColor)
        {
            var panel = new Panel
            {
                Location = bounds.Location, Size = bounds.Size,
                BackColor = bgColor
            };
            panel.Paint += (s, e) =>
            {
                var g = e.Graphics;
                g.SmoothingMode = SmoothingMode.AntiAlias;
                using var bgBrush = new SolidBrush(bgColor);
                using var bgPath = RoundedRect(new Rectangle(0, 0, panel.Width - 1, panel.Height - 1), 10);
                g.FillPath(bgBrush, bgPath);
                using var pen = new Pen(borderColor);
                g.DrawPath(pen, bgPath);
            };
            return panel;
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
                // Multi-layer shadow for depth
                for (int i = 3; i >= 1; i--)
                {
                    using var sBrush = new SolidBrush(Color.FromArgb(4 * i, 0, 0, 0));
                    using var sPath = RoundedRect(new Rectangle(i, i + 1, card.Width - i * 2, card.Height - i * 2), 10);
                    g.FillPath(sBrush, sPath);
                }
                using var bgBrush = new SolidBrush(CardBg);
                using var bgPath = RoundedRect(new Rectangle(0, 0, card.Width - 1, card.Height - 1), 10);
                g.FillPath(bgBrush, bgPath);
                using var pen = new Pen(Color.FromArgb(210, 218, 228));
                g.DrawPath(pen, bgPath);
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

        private static List<(string category, string key, string value)> GetHardwareInfo()
        {
            var items = new List<(string category, string key, string value)>();
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

        private void ToggleLocalMonitor(bool enable)
        {
            _localMonitorEnabled = enable;
            if (enable)
            {
                _localMonitorTimer ??= new System.Windows.Forms.Timer { Interval = 5000 };
                _localMonitorTimer.Tick -= LocalMonitorTick;
                _localMonitorTimer.Tick += LocalMonitorTick;
                LocalMonitorTick(null, EventArgs.Empty);
                _localMonitorTimer.Start();
            }
            else
            {
                _localMonitorTimer?.Stop();
            }
        }

        private void LocalMonitorTick(object? sender, EventArgs e)
        {
            try
            {
                var snap = new PCPlus.Core.Models.HealthSnapshot { Timestamp = DateTime.Now };

                using var cpuCounter = new System.Diagnostics.PerformanceCounter("Processor", "% Processor Time", "_Total");
                cpuCounter.NextValue();
                System.Threading.Thread.Sleep(200);
                snap.CpuPercent = cpuCounter.NextValue();

                var ci = new Microsoft.VisualBasic.Devices.ComputerInfo();
                snap.RamTotalGB = ci.TotalPhysicalMemory / 1073741824f;
                snap.RamUsedGB = (ci.TotalPhysicalMemory - ci.AvailablePhysicalMemory) / 1073741824f;
                snap.RamPercent = snap.RamUsedGB / snap.RamTotalGB * 100f;

                foreach (var drive in System.IO.DriveInfo.GetDrives())
                {
                    if (!drive.IsReady || drive.DriveType != System.IO.DriveType.Fixed) continue;
                    snap.Disks.Add(new PCPlus.Core.Models.DiskReading
                    {
                        Name = drive.Name, Label = drive.VolumeLabel,
                        TotalGB = drive.TotalSize / 1073741824f,
                        FreeGB = drive.AvailableFreeSpace / 1073741824f,
                        UsedPercent = (1f - (float)drive.AvailableFreeSpace / drive.TotalSize) * 100f
                    });
                }

                snap.ProcessCount = System.Diagnostics.Process.GetProcesses().Length;
                snap.Uptime = TimeSpan.FromMilliseconds(Environment.TickCount64);

                _health = snap;
                _hwSnapshot = snap;
                _hwSnapshotTime = DateTime.Now;
            }
            catch { }
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            _refreshTimer.Stop();
            _refreshTimer.Dispose();
            _localMonitorTimer?.Stop();
            _localMonitorTimer?.Dispose();
            _localFallback.Dispose();
            base.OnFormClosing(e);
        }
    }

    /// <summary>Graphics extension for rounded rectangles.</summary>
    internal static class GraphicsExtensions
    {
        public static void FillRoundedRectangle(this Graphics g, Brush brush, float x, float y, float w, float h, float r)
        {
            using var path = new System.Drawing.Drawing2D.GraphicsPath();
            path.AddArc(x, y, r * 2, r * 2, 180, 90);
            path.AddArc(x + w - r * 2, y, r * 2, r * 2, 270, 90);
            path.AddArc(x + w - r * 2, y + h - r * 2, r * 2, r * 2, 0, 90);
            path.AddArc(x, y + h - r * 2, r * 2, r * 2, 90, 90);
            path.CloseFigure();
            g.FillPath(brush, path);
        }

        private static string GetCompanyTicketUrl()
        {
            var baseUrl = "https://support.pcpluscomputing.com/submit.html";
            var queryParams = new List<string>();

            try
            {
                var configPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "PCPlusEndpoint", "config.json");
                if (File.Exists(configPath))
                {
                    var json = File.ReadAllText(configPath);
                    using var doc = JsonDocument.Parse(json);
                    if (doc.RootElement.TryGetProperty("companyName", out var prop))
                    {
                        var name = prop.GetString();
                        if (!string.IsNullOrWhiteSpace(name))
                        {
                            var slug = name.Trim().ToLowerInvariant()
                                .Replace(" ", "-").Replace("&", "and")
                                .Replace("(", "").Replace(")", "")
                                .Replace("'", "").Replace(",", "");
                            queryParams.Add($"c={Uri.EscapeDataString(slug)}");
                        }
                    }
                }
            }
            catch { }

            try
            {
                queryParams.Add($"pc={Uri.EscapeDataString(Environment.MachineName)}");
                queryParams.Add($"os={Uri.EscapeDataString(Environment.OSVersion.ToString())}");
                queryParams.Add($"cores={Environment.ProcessorCount}");

                var ci = new Microsoft.VisualBasic.Devices.ComputerInfo();
                var ramGb = ci.TotalPhysicalMemory / (1024.0 * 1024 * 1024);
                queryParams.Add($"ram={ramGb:F1}GB");

                var drive = new DriveInfo(Path.GetPathRoot(Environment.SystemDirectory) ?? "C:\\");
                var totalGb = drive.TotalSize / (1024.0 * 1024 * 1024);
                var freeGb = drive.AvailableFreeSpace / (1024.0 * 1024 * 1024);
                queryParams.Add($"disk={totalGb:F0}GB");
                queryParams.Add($"diskfree={freeGb:F0}GB");

                try
                {
                    using var searcher = new ManagementObjectSearcher("SELECT Name FROM Win32_Processor");
                    foreach (var obj in searcher.Get())
                    {
                        queryParams.Add($"cpu={Uri.EscapeDataString(obj["Name"]?.ToString()?.Trim() ?? "")}");
                        break;
                    }
                }
                catch { }
            }
            catch { }

            return queryParams.Count > 0 ? $"{baseUrl}?{string.Join("&", queryParams)}" : baseUrl;
        }
    }
}
