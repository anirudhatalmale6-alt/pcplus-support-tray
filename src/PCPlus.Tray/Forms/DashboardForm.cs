using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;
using PCPlus.Core.IPC;
using PCPlus.Core.Models;

namespace PCPlus.Tray.Forms
{
    /// <summary>
    /// Health Dashboard - modern dark-themed UI with donut gauges, process list,
    /// disk details, and grayed-out premium feature previews.
    /// </summary>
    public class DashboardForm : Form
    {
        private readonly IpcClient _ipc;
        private readonly System.Windows.Forms.Timer _refreshTimer;

        // Colors
        private static readonly Color BgDark = Color.FromArgb(15, 15, 22);
        private static readonly Color BgCard = Color.FromArgb(24, 24, 36);
        private static readonly Color BgCardBorder = Color.FromArgb(38, 38, 55);
        private static readonly Color TextPrimary = Color.FromArgb(235, 235, 245);
        private static readonly Color TextSecondary = Color.FromArgb(130, 130, 155);
        private static readonly Color TextMuted = Color.FromArgb(80, 80, 100);
        private static readonly Color AccentBlue = Color.FromArgb(56, 132, 255);
        private static readonly Color AccentGreen = Color.FromArgb(48, 209, 88);
        private static readonly Color AccentOrange = Color.FromArgb(255, 159, 10);
        private static readonly Color AccentRed = Color.FromArgb(255, 69, 58);
        private static readonly Color AccentPurple = Color.FromArgb(175, 82, 222);
        private static readonly Color PremiumOverlay = Color.FromArgb(180, 15, 15, 22);

        // Data
        private HealthSnapshot? _health;
        private ServiceStatusReport? _serviceStatus;

        // UI Controls
        private Panel _headerPanel = null!;
        private Panel _contentPanel = null!;
        private Label _statusLabel = null!;
        private Label _statusDot = null!;
        private Label _uptimeLabel = null!;
        private Label _scoreLabel = null!;

        // Donut gauges
        private DonutGauge _cpuDonut = null!;
        private DonutGauge _ramDonut = null!;
        private DonutGauge _diskDonut = null!;
        private DonutGauge _tempDonut = null!;

        // Detail panels
        private Panel _processPanel = null!;
        private Panel _diskPanel = null!;
        private Panel _networkPanel = null!;
        private Panel _premiumPanel = null!;

        public DashboardForm(IpcClient ipc)
        {
            _ipc = ipc;
            InitializeForm();
            BuildUI();

            _refreshTimer = new System.Windows.Forms.Timer { Interval = 3000 };
            _refreshTimer.Tick += async (s, e) => await RefreshData();
            _refreshTimer.Start();

            _ = RefreshData();
        }

        private void InitializeForm()
        {
            Text = "PC Plus Endpoint Protection";
            Size = new Size(900, 720);
            StartPosition = FormStartPosition.CenterScreen;
            BackColor = BgDark;
            ForeColor = TextPrimary;
            FormBorderStyle = FormBorderStyle.FixedSingle;
            MaximizeBox = false;
            Font = new Font("Segoe UI", 9.5f);
            DoubleBuffered = true;
        }

        private void BuildUI()
        {
            // === HEADER ===
            _headerPanel = new Panel
            {
                Dock = DockStyle.Top, Height = 70, BackColor = BgCard
            };
            _headerPanel.Paint += (s, e) =>
            {
                using var pen = new Pen(BgCardBorder);
                e.Graphics.DrawLine(pen, 0, _headerPanel.Height - 1, _headerPanel.Width, _headerPanel.Height - 1);
            };

            _statusDot = new Label
            {
                Text = "\u25CF", AutoSize = true,
                Font = new Font("Segoe UI", 11),
                ForeColor = AccentOrange, Location = new Point(20, 14)
            };

            var titleLabel = new Label
            {
                Text = "Device is protected", AutoSize = true,
                Font = new Font("Segoe UI Semibold", 15, FontStyle.Bold),
                ForeColor = TextPrimary, Location = new Point(42, 10)
            };

            _statusLabel = new Label
            {
                Text = "Connecting to service...", AutoSize = true,
                Font = new Font("Segoe UI", 9),
                ForeColor = TextSecondary, Location = new Point(44, 38)
            };

            _scoreLabel = new Label
            {
                Text = "Score: --/100", AutoSize = true,
                Font = new Font("Segoe UI Semibold", 10),
                ForeColor = AccentBlue, Location = new Point(260, 38)
            };

            _uptimeLabel = new Label
            {
                Text = "", AutoSize = true,
                Font = new Font("Segoe UI", 9),
                ForeColor = TextSecondary,
                Anchor = AnchorStyles.Top | AnchorStyles.Right,
                Location = new Point(700, 26)
            };

            _headerPanel.Controls.AddRange(new Control[] { _statusDot, titleLabel, _statusLabel, _scoreLabel, _uptimeLabel });

            // === CONTENT ===
            _contentPanel = new Panel
            {
                Dock = DockStyle.Fill, AutoScroll = true,
                BackColor = BgDark, Padding = new Padding(20, 12, 20, 20)
            };

            // --- Donut Gauge Row ---
            var gaugeRow = new Panel
            {
                Location = new Point(20, 8),
                Size = new Size(844, 170),
                BackColor = Color.Transparent
            };

            int gaugeW = 200, gap = 12;
            _cpuDonut = new DonutGauge("CPU", "%", AccentBlue) { Location = new Point(0, 0), Size = new Size(gaugeW, 165) };
            _ramDonut = new DonutGauge("Memory", "%", AccentGreen) { Location = new Point(gaugeW + gap, 0), Size = new Size(gaugeW, 165) };
            _diskDonut = new DonutGauge("Disk", "%", AccentOrange) { Location = new Point((gaugeW + gap) * 2, 0), Size = new Size(gaugeW, 165) };
            _tempDonut = new DonutGauge("Temp", "\u00B0C", AccentRed) { Location = new Point((gaugeW + gap) * 3, 0), Size = new Size(gaugeW, 165) };

            gaugeRow.Controls.AddRange(new Control[] { _cpuDonut, _ramDonut, _diskDonut, _tempDonut });

            // --- Process List ---
            _processPanel = CreateCard("Top Processes", new Point(20, 185), new Size(420, 210));

            // --- Disk & Network Info ---
            _diskPanel = CreateCard("Storage", new Point(452, 185), new Size(412, 100));
            _networkPanel = CreateCard("Network & System", new Point(452, 295), new Size(412, 100));

            // --- Premium Features Preview ---
            _premiumPanel = CreatePremiumPanel(new Point(20, 405), new Size(844, 170));

            _contentPanel.Controls.AddRange(new Control[] { gaugeRow, _processPanel, _diskPanel, _networkPanel, _premiumPanel });

            Controls.Add(_contentPanel);
            Controls.Add(_headerPanel);
        }

        private Panel CreateCard(string title, Point location, Size size)
        {
            var panel = new Panel
            {
                Location = location, Size = size,
                BackColor = BgCard
            };
            panel.Paint += (s, e) =>
            {
                using var pen = new Pen(BgCardBorder);
                var r = new Rectangle(0, 0, panel.Width - 1, panel.Height - 1);
                DrawRoundedRect(e.Graphics, pen, r, 6);
            };

            var lbl = new Label
            {
                Text = title, AutoSize = true, Location = new Point(14, 10),
                Font = new Font("Segoe UI Semibold", 10, FontStyle.Bold),
                ForeColor = TextPrimary, BackColor = Color.Transparent
            };
            panel.Controls.Add(lbl);
            panel.Tag = lbl;
            return panel;
        }

        private Panel CreatePremiumPanel(Point location, Size size)
        {
            var panel = new Panel
            {
                Location = location, Size = size,
                BackColor = BgCard
            };
            panel.Paint += (s, e) =>
            {
                var g = e.Graphics;
                g.SmoothingMode = SmoothingMode.AntiAlias;

                // Card border
                using var borderPen = new Pen(BgCardBorder);
                var r = new Rectangle(0, 0, panel.Width - 1, panel.Height - 1);
                DrawRoundedRect(g, borderPen, r, 6);

                // Title
                using var titleFont = new Font("Segoe UI Semibold", 10, FontStyle.Bold);
                using var titleBrush = new SolidBrush(TextPrimary);
                g.DrawString("Advanced Protection", titleFont, titleBrush, 14, 10);

                // Premium feature cards (grayed out)
                var features = new[]
                {
                    ("Ransomware Shield", "Real-time file protection\nand rollback recovery", "\uD83D\uDEE1"),
                    ("AI Threat Analysis", "Intelligent behavioral\nthreat detection", "\uD83E\uDDE0"),
                    ("Remote Lockdown", "Instantly lock device\nfrom dashboard", "\uD83D\uDD12"),
                    ("Backup & Recovery", "Automated cloud backup\nwith one-click restore", "\u2601")
                };

                int cardW = 195, cardH = 100, startX = 14, startY = 38, cardGap = 10;
                using var cardBg = new SolidBrush(Color.FromArgb(20, 20, 32));
                using var cardBorder = new Pen(Color.FromArgb(35, 35, 50));
                using var featureFont = new Font("Segoe UI Semibold", 9.5f, FontStyle.Bold);
                using var descFont = new Font("Segoe UI", 8f);
                using var iconFont = new Font("Segoe UI", 20f);
                using var grayText = new SolidBrush(Color.FromArgb(70, 70, 90));
                using var grayIcon = new SolidBrush(Color.FromArgb(50, 50, 70));

                for (int i = 0; i < features.Length; i++)
                {
                    var (name, desc, icon) = features[i];
                    var cardRect = new Rectangle(startX + i * (cardW + cardGap), startY, cardW, cardH);
                    g.FillRectangle(cardBg, cardRect);
                    DrawRoundedRect(g, cardBorder, cardRect, 4);

                    g.DrawString(icon, iconFont, grayIcon, cardRect.X + 10, cardRect.Y + 8);
                    g.DrawString(name, featureFont, grayText, cardRect.X + 10, cardRect.Y + 42);
                    g.DrawString(desc, descFont, grayText, cardRect.X + 10, cardRect.Y + 62);
                }

                // Overlay badge
                using var badgeBg = new SolidBrush(Color.FromArgb(230, AccentPurple.R, AccentPurple.G, AccentPurple.B));
                using var badgeFont = new Font("Segoe UI Semibold", 9f, FontStyle.Bold);
                using var badgeText = new SolidBrush(Color.White);

                string badge = " \u2B50 Upgrade to Premium ";
                var badgeSize = g.MeasureString(badge, badgeFont);
                var badgeRect = new RectangleF(
                    panel.Width - badgeSize.Width - 20, 8,
                    badgeSize.Width + 8, badgeSize.Height + 4);

                var badgePath = GetRoundedRectPath(Rectangle.Round(badgeRect), 10);
                g.FillPath(badgeBg, badgePath);
                g.DrawString(badge, badgeFont, badgeText, badgeRect.X + 4, badgeRect.Y + 2);
            };

            return panel;
        }

        private async Task RefreshData()
        {
            try
            {
                if (!_ipc.IsConnected)
                {
                    try { await Task.Run(() => _ipc.ConnectAsync(5000)); }
                    catch { }
                }

                if (!_ipc.IsConnected)
                {
                    if (InvokeRequired)
                        Invoke(new Action(() =>
                        {
                            _statusLabel.Text = "Connecting to service...";
                            _statusDot.ForeColor = AccentOrange;
                        }));
                    return;
                }

                var healthResponse = await Task.Run(() => _ipc.GetHealthSnapshotAsync());
                if (healthResponse.Success)
                {
                    _health = healthResponse.GetData<HealthSnapshot>();
                    if (_health != null)
                        UpdateAll();
                }
                else
                {
                    if (InvokeRequired)
                        Invoke(new Action(() =>
                        {
                            _statusLabel.Text = $"Waiting for data...";
                            _statusDot.ForeColor = AccentBlue;
                        }));
                }

                var statusResponse = await Task.Run(() => _ipc.GetServiceStatusAsync());
                if (statusResponse.Success)
                    _serviceStatus = statusResponse.GetData<ServiceStatusReport>();
            }
            catch { }
        }

        private void UpdateAll()
        {
            if (_health == null) return;
            if (InvokeRequired) { Invoke(new Action(UpdateAll)); return; }

            // Donuts
            _cpuDonut.SetValue(_health.CpuPercent, 100, $"{_health.CpuPercent:F0}%");
            _ramDonut.SetValue(_health.RamPercent, 100,
                $"{_health.RamPercent:F0}%",
                $"{_health.RamUsedGB:F1} / {_health.RamTotalGB:F1} GB");

            var disk = _health.Disks.FirstOrDefault();
            float diskPct = disk?.UsedPercent ?? 0;
            float diskUsed = disk != null ? disk.TotalGB - disk.FreeGB : 0;
            float diskTotal = disk?.TotalGB ?? 0;
            _diskDonut.SetValue(diskPct, 100,
                $"{diskPct:F0}%",
                disk != null ? $"{diskUsed:F0} / {diskTotal:F0} GB" : "");

            _tempDonut.SetValue(_health.CpuTempC, 100,
                _health.CpuTempC > 0 ? $"{_health.CpuTempC:F0}\u00B0" : "--",
                _health.CpuTempC > 0 ? "" : "No sensor");

            // Uptime
            if (_health.Uptime.TotalMinutes > 0)
            {
                var up = _health.Uptime;
                _uptimeLabel.Text = $"Uptime: {(int)up.TotalDays}d {up.Hours}h {up.Minutes}m";
            }

            // Score
            // Simple security score estimate: penalize high CPU, high disk, high temp
            int score = 100;
            if (_health.CpuPercent > 90) score -= 20;
            else if (_health.CpuPercent > 70) score -= 10;
            if (diskPct > 90) score -= 25;
            else if (diskPct > 80) score -= 10;
            if (_health.CpuTempC > 85) score -= 20;
            else if (_health.CpuTempC > 75) score -= 10;
            if (_health.RamPercent > 90) score -= 15;
            else if (_health.RamPercent > 80) score -= 5;
            score = Math.Max(0, Math.Min(100, score));

            _scoreLabel.Text = $"Score: {score}/100";
            _scoreLabel.ForeColor = score >= 80 ? AccentGreen : score >= 50 ? AccentOrange : AccentRed;

            // Status
            _statusLabel.Text = $"{_health.ProcessCount} processes running";
            _statusDot.ForeColor = AccentGreen;

            UpdateProcessList();
            UpdateDiskInfo();
            UpdateNetworkInfo();
        }

        private void UpdateProcessList()
        {
            if (_health?.TopProcesses == null) return;

            var toRemove = _processPanel.Controls.OfType<Control>()
                .Where(c => c != (Label)_processPanel.Tag!).ToList();
            foreach (var c in toRemove) { _processPanel.Controls.Remove(c); c.Dispose(); }

            // Column headers
            int y = 34;
            var headerPanel = new Panel
            {
                Location = new Point(0, y), Size = new Size(_processPanel.Width, 22),
                BackColor = Color.FromArgb(20, 20, 30)
            };
            var hdrName = new Label { Text = "Process", Location = new Point(14, 3), AutoSize = true,
                Font = new Font("Segoe UI", 8f, FontStyle.Bold), ForeColor = TextSecondary, BackColor = Color.Transparent };
            var hdrCpu = new Label { Text = "CPU", Location = new Point(250, 3), AutoSize = true,
                Font = new Font("Segoe UI", 8f, FontStyle.Bold), ForeColor = TextSecondary, BackColor = Color.Transparent };
            var hdrMem = new Label { Text = "Memory", Location = new Point(320, 3), AutoSize = true,
                Font = new Font("Segoe UI", 8f, FontStyle.Bold), ForeColor = TextSecondary, BackColor = Color.Transparent };
            headerPanel.Controls.AddRange(new Control[] { hdrName, hdrCpu, hdrMem });
            _processPanel.Controls.Add(headerPanel);
            y += 24;

            int row = 0;
            foreach (var proc in _health.TopProcesses.Take(8))
            {
                var rowBg = row % 2 == 0 ? Color.Transparent : Color.FromArgb(18, 18, 28);
                var rowPanel = new Panel
                {
                    Location = new Point(0, y), Size = new Size(_processPanel.Width, 18),
                    BackColor = rowBg
                };

                var name = proc.Name.Length > 28 ? proc.Name.Substring(0, 28) : proc.Name;
                var cpuColor = proc.CpuPercent > 50 ? AccentRed : proc.CpuPercent > 20 ? AccentOrange : TextSecondary;

                var lblName = new Label { Text = name, Location = new Point(14, 1), AutoSize = true,
                    Font = new Font("Segoe UI", 8.5f), ForeColor = TextPrimary, BackColor = Color.Transparent };
                var lblCpu = new Label { Text = $"{proc.CpuPercent:F1}%", Location = new Point(250, 1), AutoSize = true,
                    Font = new Font("Consolas", 8.5f), ForeColor = cpuColor, BackColor = Color.Transparent };
                var lblMem = new Label { Text = $"{proc.MemoryMB:F0} MB", Location = new Point(320, 1), AutoSize = true,
                    Font = new Font("Consolas", 8.5f), ForeColor = TextSecondary, BackColor = Color.Transparent };

                rowPanel.Controls.AddRange(new Control[] { lblName, lblCpu, lblMem });
                _processPanel.Controls.Add(rowPanel);
                y += 19;
                row++;
            }
        }

        private void UpdateDiskInfo()
        {
            if (_health?.Disks == null) return;

            var toRemove = _diskPanel.Controls.OfType<Control>()
                .Where(c => c != (Label)_diskPanel.Tag!).ToList();
            foreach (var c in toRemove) { _diskPanel.Controls.Remove(c); c.Dispose(); }

            int y = 34;
            foreach (var disk in _health.Disks.Take(3))
            {
                var pctColor = disk.UsedPercent > 90 ? AccentRed : disk.UsedPercent > 75 ? AccentOrange : AccentGreen;
                var barColor = pctColor;

                // Drive label
                var lbl = new Label
                {
                    Text = $"{disk.Name}  {disk.Label}",
                    Location = new Point(14, y), AutoSize = true,
                    Font = new Font("Segoe UI", 8.5f), ForeColor = TextPrimary, BackColor = Color.Transparent
                };
                _diskPanel.Controls.Add(lbl);

                // Usage text
                var usageText = new Label
                {
                    Text = $"{disk.FreeGB:F0} GB free / {disk.TotalGB:F0} GB",
                    Location = new Point(200, y), AutoSize = true,
                    Font = new Font("Segoe UI", 8.5f), ForeColor = TextSecondary, BackColor = Color.Transparent
                };
                _diskPanel.Controls.Add(usageText);

                // Progress bar
                var barPanel = new Panel { Location = new Point(14, y + 18), Size = new Size(380, 6), BackColor = Color.FromArgb(35, 35, 50) };
                barPanel.Paint += (s, e) =>
                {
                    var pct = disk.UsedPercent / 100f;
                    var w = (int)(barPanel.Width * pct);
                    using var brush = new SolidBrush(barColor);
                    e.Graphics.FillRectangle(brush, 0, 0, w, barPanel.Height);
                };
                _diskPanel.Controls.Add(barPanel);
                y += 30;
            }
        }

        private void UpdateNetworkInfo()
        {
            if (_health == null) return;

            var toRemove = _networkPanel.Controls.OfType<Control>()
                .Where(c => c != (Label)_networkPanel.Tag!).ToList();
            foreach (var c in toRemove) { _networkPanel.Controls.Remove(c); c.Dispose(); }

            int y = 34;
            var items = new[]
            {
                ($"\u2191 {_health.NetworkSentKBps:F0} KB/s", $"\u2193 {_health.NetworkRecvKBps:F0} KB/s",
                 $"Processes: {_health.ProcessCount}",
                 $"GPU: {(_health.GpuTempC > 0 ? $"{_health.GpuTempC:F0}\u00B0C" : "N/A")}")
            };

            foreach (var (up, down, procs, gpu) in items)
            {
                int x = 14;
                foreach (var item in new[] { up, down, procs, gpu })
                {
                    var lbl = new Label
                    {
                        Text = item, Location = new Point(x, y), AutoSize = true,
                        Font = new Font("Segoe UI", 8.5f), ForeColor = TextSecondary, BackColor = Color.Transparent
                    };
                    _networkPanel.Controls.Add(lbl);
                    x += 100;
                }
                y += 20;
            }
        }

        private static void DrawRoundedRect(Graphics g, Pen pen, Rectangle rect, int radius)
        {
            using var path = GetRoundedRectPath(rect, radius);
            g.DrawPath(pen, path);
        }

        private static GraphicsPath GetRoundedRectPath(Rectangle rect, int radius)
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

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            _refreshTimer.Stop();
            _refreshTimer.Dispose();
            base.OnFormClosing(e);
        }
    }

    /// <summary>Modern donut gauge with center value display and subtitle.</summary>
    internal class DonutGauge : Panel
    {
        private float _value;
        private float _maxValue = 100;
        private string _label;
        private string _unit;
        private string _displayValue = "--";
        private string _subText = "";
        private Color _accentColor;

        private static readonly Color BgColor = Color.FromArgb(24, 24, 36);
        private static readonly Color TrackColor = Color.FromArgb(35, 35, 50);
        private static readonly Color TextColor = Color.FromArgb(235, 235, 245);
        private static readonly Color SubTextColor = Color.FromArgb(130, 130, 155);

        public DonutGauge(string label, string unit, Color accent)
        {
            _label = label;
            _unit = unit;
            _accentColor = accent;
            BackColor = BgColor;
            DoubleBuffered = true;
            Margin = new Padding(4);

            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint | ControlStyles.OptimizedDoubleBuffer, true);
        }

        public void SetValue(float value, float max, string? displayValue = null, string? subText = null)
        {
            _value = Math.Max(0, Math.Min(value, max));
            _maxValue = max;
            if (displayValue != null) _displayValue = displayValue;
            if (subText != null) _subText = subText;
            Invalidate();
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

            // Card background with rounded corners
            using var bgBrush = new SolidBrush(BgColor);
            g.FillRectangle(bgBrush, ClientRectangle);
            using var borderPen = new Pen(Color.FromArgb(38, 38, 55));
            var cardRect = new Rectangle(0, 0, Width - 1, Height - 1);
            var path = new GraphicsPath();
            int r = 8;
            path.AddArc(cardRect.X, cardRect.Y, r*2, r*2, 180, 90);
            path.AddArc(cardRect.Right - r*2, cardRect.Y, r*2, r*2, 270, 90);
            path.AddArc(cardRect.Right - r*2, cardRect.Bottom - r*2, r*2, r*2, 0, 90);
            path.AddArc(cardRect.X, cardRect.Bottom - r*2, r*2, r*2, 90, 90);
            path.CloseFigure();
            g.DrawPath(borderPen, path);

            // Donut dimensions
            int donutSize = 100;
            int thickness = 10;
            var donutRect = new Rectangle((Width - donutSize) / 2, 12, donutSize, donutSize);

            // Track (background circle)
            using var trackPen = new Pen(TrackColor, thickness) { StartCap = LineCap.Round, EndCap = LineCap.Round };
            g.DrawArc(trackPen, donutRect, 0, 360);

            // Value arc
            float pct = _maxValue > 0 ? _value / _maxValue : 0;
            float sweepAngle = pct * 360f;
            if (sweepAngle > 0.5f)
            {
                var arcColor = pct > 0.9f ? Color.FromArgb(255, 69, 58) :
                    pct > 0.75f ? Color.FromArgb(255, 159, 10) : _accentColor;
                using var valuePen = new Pen(arcColor, thickness) { StartCap = LineCap.Round, EndCap = LineCap.Round };
                g.DrawArc(valuePen, donutRect, -90, sweepAngle);
            }

            // Center value text
            using var valueFont = new Font("Segoe UI Semibold", 16, FontStyle.Bold);
            using var textBrush = new SolidBrush(TextColor);
            var valSize = g.MeasureString(_displayValue, valueFont);
            g.DrawString(_displayValue, valueFont, textBrush,
                donutRect.X + (donutRect.Width - valSize.Width) / 2,
                donutRect.Y + (donutRect.Height - valSize.Height) / 2);

            // Label below donut
            using var labelFont = new Font("Segoe UI Semibold", 9.5f);
            var labelSize = g.MeasureString(_label, labelFont);
            g.DrawString(_label, labelFont, textBrush, (Width - labelSize.Width) / 2, donutRect.Bottom + 8);

            // Sub-text (e.g., "4.2 / 8.0 GB")
            if (!string.IsNullOrEmpty(_subText))
            {
                using var subFont = new Font("Segoe UI", 8f);
                using var subBrush = new SolidBrush(SubTextColor);
                var subSize = g.MeasureString(_subText, subFont);
                g.DrawString(_subText, subFont, subBrush, (Width - subSize.Width) / 2, donutRect.Bottom + 26);
            }

            path.Dispose();
        }
    }
}
