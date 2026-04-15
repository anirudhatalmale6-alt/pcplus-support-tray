using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Text;
using System.Linq;
using System.Windows.Forms;

namespace SupportTray
{
    /// <summary>
    /// Modern dark-theme health dashboard with real-time gauges, charts, and security score.
    /// Custom-drawn WinForms with double-buffered panels for smooth rendering.
    /// </summary>
    public class HealthDashboardForm : Form
    {
        private readonly AppConfig _config;
        private readonly HealthMonitor _monitor;
        private SecurityScanner? _securityScanner;
        private System.Windows.Forms.Timer _uiTimer = null!;

        // UI panels
        private DashboardPanel _cpuPanel = null!;
        private DashboardPanel _ramPanel = null!;
        private DashboardPanel _diskPanel = null!;
        private DashboardPanel _tempPanel = null!;
        private DashboardPanel _networkPanel = null!;
        private DashboardPanel _securityPanel = null!;
        private DashboardPanel _processPanel = null!;
        private DashboardPanel _uptimePanel = null!;

        // History for mini sparklines
        private readonly Queue<float> _cpuHistory = new();
        private readonly Queue<float> _ramHistory = new();
        private readonly Queue<float> _netSendHistory = new();
        private readonly Queue<float> _netRecvHistory = new();
        private const int HISTORY_LENGTH = 60; // 60 data points

        // Colors
        private static readonly Color BgDark = Color.FromArgb(18, 18, 24);
        private static readonly Color BgCard = Color.FromArgb(28, 30, 40);
        private static readonly Color BgCardHover = Color.FromArgb(35, 38, 52);
        private static readonly Color AccentBlue = Color.FromArgb(59, 130, 246);
        private static readonly Color AccentGreen = Color.FromArgb(34, 197, 94);
        private static readonly Color AccentYellow = Color.FromArgb(250, 204, 21);
        private static readonly Color AccentRed = Color.FromArgb(239, 68, 68);
        private static readonly Color AccentOrange = Color.FromArgb(249, 115, 22);
        private static readonly Color AccentPurple = Color.FromArgb(168, 85, 247);
        private static readonly Color AccentCyan = Color.FromArgb(6, 182, 212);
        private static readonly Color TextPrimary = Color.FromArgb(240, 240, 250);
        private static readonly Color TextSecondary = Color.FromArgb(148, 163, 184);
        private static readonly Color TextMuted = Color.FromArgb(100, 116, 139);

        public HealthDashboardForm(AppConfig config, HealthMonitor monitor)
        {
            _config = config;
            _monitor = monitor;
            InitializeUI();
        }

        private void InitializeUI()
        {
            Text = $"{_config.CompanyName} - System Health Dashboard";
            Size = new Size(920, 680);
            MinimumSize = new Size(800, 600);
            StartPosition = FormStartPosition.CenterScreen;
            BackColor = BgDark;
            DoubleBuffered = true;
            Font = new Font("Segoe UI", 9.5f);

            // Header bar
            var header = new Panel
            {
                Dock = DockStyle.Top,
                Height = 56,
                BackColor = Color.FromArgb(22, 24, 32)
            };
            header.Paint += (s, e) =>
            {
                var g = e.Graphics;
                g.TextRenderingHint = TextRenderingHint.ClearTypeGridFit;

                // Logo circle
                using var circleBrush = new SolidBrush(AccentBlue);
                g.FillEllipse(circleBrush, 16, 12, 32, 32);
                using var logoFont = new Font("Segoe UI", 10, FontStyle.Bold);
                using var whiteBrush = new SolidBrush(Color.White);
                var sz = g.MeasureString("PC", logoFont);
                g.DrawString("PC", logoFont, whiteBrush, 16 + (32 - sz.Width) / 2, 12 + (32 - sz.Height) / 2);

                // Title
                using var titleFont = new Font("Segoe UI", 14, FontStyle.Bold);
                g.DrawString("System Health", titleFont, whiteBrush, 58, 8);

                // Subtitle
                using var subFont = new Font("Segoe UI", 8.5f);
                using var subBrush = new SolidBrush(TextSecondary);
                g.DrawString("Real-time monitoring", subFont, subBrush, 60, 32);

                // Version + status on right
                var versionText = $"v{GetVersion()}";
                using var verFont = new Font("Segoe UI", 8f);
                var vsz = g.MeasureString(versionText, verFont);
                g.DrawString(versionText, verFont, subBrush, header.Width - vsz.Width - 16, 20);

                // Bottom accent line
                using var linePen = new Pen(AccentBlue, 2);
                g.DrawLine(linePen, 0, header.Height - 1, header.Width, header.Height - 1);
            };
            Controls.Add(header);

            // Scrollable content area
            var content = new Panel
            {
                Dock = DockStyle.Fill,
                AutoScroll = true,
                BackColor = BgDark,
                Padding = new Padding(16, 12, 16, 12)
            };
            Controls.Add(content);
            content.BringToFront();

            // Create dashboard panels
            _cpuPanel = CreateCard("CPU", 0, 0);
            _ramPanel = CreateCard("Memory", 1, 0);
            _tempPanel = CreateCard("Temperatures", 2, 0);
            _securityPanel = CreateCard("Security Score", 3, 0);
            _diskPanel = CreateCard("Storage", 0, 1);
            _networkPanel = CreateCard("Network", 1, 1);
            _processPanel = CreateCard("Top Processes", 2, 1);
            _uptimePanel = CreateCard("System Info", 3, 1);

            content.Controls.AddRange(new Control[] {
                _cpuPanel, _ramPanel, _tempPanel, _securityPanel,
                _diskPanel, _networkPanel, _processPanel, _uptimePanel
            });

            // Layout on resize
            content.Resize += (s, e) => LayoutCards(content);
            Load += (s, e) =>
            {
                LayoutCards(content);
                // Run security scan in background
                System.Threading.Tasks.Task.Run(() =>
                {
                    _securityScanner = new SecurityScanner();
                    _securityScanner.RunFullScan();
                    if (!IsDisposed)
                        Invoke(() => _securityPanel.Invalidate());
                });
            };

            // UI refresh timer (separate from monitor's poll timer)
            _uiTimer = new System.Windows.Forms.Timer { Interval = 1000 };
            _uiTimer.Tick += (s, e) => UpdateUI();
            _uiTimer.Start();

            FormClosing += (s, e) =>
            {
                _uiTimer.Stop();
                _uiTimer.Dispose();
            };
        }

        private void LayoutCards(Panel container)
        {
            var w = container.ClientSize.Width - 32; // padding
            var cardW = (w - 12) / 2; // 2 columns with gap
            var cardH = 150;
            var gap = 12;

            var cards = new[] { _cpuPanel, _diskPanel, _ramPanel, _networkPanel,
                               _tempPanel, _processPanel, _securityPanel, _uptimePanel };

            for (int i = 0; i < cards.Length; i++)
            {
                int col = i % 2;
                int row = i / 2;
                cards[i].Location = new Point(col * (cardW + gap), row * (cardH + gap));
                cards[i].Size = new Size(cardW, cardH);
            }
        }

        private DashboardPanel CreateCard(string title, int row, int col)
        {
            var panel = new DashboardPanel
            {
                Title = title,
                Size = new Size(400, 150)
            };
            panel.CustomPaint += (g, bounds) => PaintCard(g, bounds, title);
            return panel;
        }

        private void UpdateUI()
        {
            if (IsDisposed) return;

            var snap = _monitor.GetSnapshot();

            // Update history queues
            _cpuHistory.Enqueue(snap.CpuPercent);
            _ramHistory.Enqueue(snap.RamPercent);
            _netSendHistory.Enqueue(snap.NetworkSentKBps);
            _netRecvHistory.Enqueue(snap.NetworkRecvKBps);

            while (_cpuHistory.Count > HISTORY_LENGTH) _cpuHistory.Dequeue();
            while (_ramHistory.Count > HISTORY_LENGTH) _ramHistory.Dequeue();
            while (_netSendHistory.Count > HISTORY_LENGTH) _netSendHistory.Dequeue();
            while (_netRecvHistory.Count > HISTORY_LENGTH) _netRecvHistory.Dequeue();

            // Repaint all cards
            _cpuPanel.Invalidate();
            _ramPanel.Invalidate();
            _diskPanel.Invalidate();
            _tempPanel.Invalidate();
            _networkPanel.Invalidate();
            _processPanel.Invalidate();
            _uptimePanel.Invalidate();
        }

        private void PaintCard(Graphics g, Rectangle bounds, string title)
        {
            var snap = _monitor.GetSnapshot();

            switch (title)
            {
                case "CPU":
                    PaintGaugeCard(g, bounds, "CPU", snap.CpuPercent, "%",
                        $"{snap.CpuPercent:F0}%", SystemInfo.GetCPU(),
                        AccentBlue, _cpuHistory.ToArray());
                    break;

                case "Memory":
                    PaintGaugeCard(g, bounds, "Memory", snap.RamPercent, "%",
                        $"{snap.RamUsedGB:F1} / {snap.RamTotalGB:F1} GB",
                        $"{snap.RamPercent:F0}% used",
                        AccentPurple, _ramHistory.ToArray());
                    break;

                case "Storage":
                    PaintDiskCard(g, bounds, snap.Disks);
                    break;

                case "Temperatures":
                    PaintTempCard(g, bounds, snap);
                    break;

                case "Network":
                    PaintNetworkCard(g, bounds, snap);
                    break;

                case "Security Score":
                    PaintSecurityCard(g, bounds);
                    break;

                case "Top Processes":
                    PaintProcessCard(g, bounds, snap);
                    break;

                case "System Info":
                    PaintSystemInfoCard(g, bounds, snap);
                    break;
            }
        }

        private void PaintGaugeCard(Graphics g, Rectangle bounds, string title, float value,
            string unit, string subtitle, string detail, Color accent, float[] history)
        {
            var cx = bounds.X + 70;
            var cy = bounds.Y + 75;
            var radius = 45;

            // Arc gauge background
            using var bgPen = new Pen(Color.FromArgb(40, 45, 60), 8);
            g.DrawArc(bgPen, cx - radius, cy - radius, radius * 2, radius * 2, 135, 270);

            // Arc gauge value
            var sweepAngle = value / 100f * 270f;
            var color = value > 90 ? AccentRed : value > 75 ? AccentOrange : accent;
            using var valuePen = new Pen(color, 8);
            valuePen.StartCap = LineCap.Round;
            valuePen.EndCap = LineCap.Round;
            if (sweepAngle > 0)
                g.DrawArc(valuePen, cx - radius, cy - radius, radius * 2, radius * 2, 135, sweepAngle);

            // Center text
            using var bigFont = new Font("Segoe UI", 18, FontStyle.Bold);
            using var textBrush = new SolidBrush(TextPrimary);
            var txt = $"{value:F0}";
            var tsz = g.MeasureString(txt, bigFont);
            g.DrawString(txt, bigFont, textBrush, cx - tsz.Width / 2, cy - tsz.Height / 2 - 4);

            using var unitFont = new Font("Segoe UI", 8);
            using var mutedBrush = new SolidBrush(TextMuted);
            var usz = g.MeasureString(unit, unitFont);
            g.DrawString(unit, unitFont, mutedBrush, cx - usz.Width / 2, cy + tsz.Height / 2 - 8);

            // Right side: sparkline + details
            var rx = bounds.X + 150;
            var ry = bounds.Y + 20;

            using var titleFont = new Font("Segoe UI", 9, FontStyle.Bold);
            using var subFont = new Font("Segoe UI", 8.5f);
            using var detailFont = new Font("Segoe UI", 7.5f);
            using var subBrush = new SolidBrush(TextSecondary);

            g.DrawString(subtitle, subFont, subBrush, rx, ry);
            g.DrawString(detail, detailFont, mutedBrush, rx, ry + 18);

            // Sparkline
            if (history.Length > 2)
            {
                var sparkX = rx;
                var sparkY = ry + 42;
                var sparkW = bounds.Right - rx - 16;
                var sparkH = bounds.Bottom - sparkY - 16;
                DrawSparkline(g, sparkX, sparkY, sparkW, sparkH, history, color);
            }
        }

        private void PaintDiskCard(Graphics g, Rectangle bounds, List<DiskReading> disks)
        {
            var y = bounds.Y + 12;
            var x = bounds.X + 16;
            var barW = bounds.Width - 40;

            using var nameFont = new Font("Segoe UI", 9, FontStyle.Bold);
            using var detailFont = new Font("Segoe UI", 7.5f);
            using var textBrush = new SolidBrush(TextPrimary);
            using var subBrush = new SolidBrush(TextSecondary);
            using var mutedBrush = new SolidBrush(TextMuted);

            foreach (var disk in disks.Take(3)) // Show up to 3 drives
            {
                var label = string.IsNullOrEmpty(disk.Label) ? disk.Name : $"{disk.Name} ({disk.Label})";
                g.DrawString(label, nameFont, textBrush, x, y);

                var freeText = $"{disk.FreeGB:F1} GB free of {disk.TotalGB:F0} GB";
                var fsz = g.MeasureString(freeText, detailFont);
                g.DrawString(freeText, detailFont, subBrush, bounds.Right - fsz.Width - 20, y + 2);

                y += 20;

                // Progress bar
                var barH = 10;
                var barRect = new Rectangle(x, y, barW, barH);

                // Background
                using var bgPath = CreateRoundRect(barRect, 5);
                using var bgBrush = new SolidBrush(Color.FromArgb(40, 45, 60));
                g.FillPath(bgBrush, bgPath);

                // Fill
                var fillW = (int)(barW * disk.UsedPercent / 100f);
                if (fillW > 0)
                {
                    var fillRect = new Rectangle(x, y, Math.Max(fillW, 10), barH);
                    using var fillPath = CreateRoundRect(fillRect, 5);
                    var fillColor = disk.UsedPercent > 90 ? AccentRed :
                                    disk.UsedPercent > 75 ? AccentOrange : AccentCyan;
                    using var fillBrush = new SolidBrush(fillColor);
                    g.FillPath(fillBrush, fillPath);
                }

                // Percentage text
                var pctText = $"{disk.UsedPercent:F0}%";
                using var pctFont = new Font("Segoe UI", 7, FontStyle.Bold);
                g.DrawString(pctText, pctFont, mutedBrush, x + barW + 4, y - 1);

                y += barH + 12;
            }

            if (disks.Count == 0)
            {
                g.DrawString("No fixed drives detected", detailFont, mutedBrush, x, y);
            }
        }

        private void PaintTempCard(Graphics g, Rectangle bounds, HealthSnapshot snap)
        {
            var x = bounds.X + 16;
            var y = bounds.Y + 12;

            using var labelFont = new Font("Segoe UI", 9, FontStyle.Bold);
            using var valueFont = new Font("Segoe UI", 22, FontStyle.Bold);
            using var detailFont = new Font("Segoe UI", 7.5f);
            using var textBrush = new SolidBrush(TextPrimary);
            using var subBrush = new SolidBrush(TextSecondary);
            using var mutedBrush = new SolidBrush(TextMuted);

            // CPU Temperature
            g.DrawString("CPU", labelFont, subBrush, x, y);
            y += 18;

            if (snap.CpuTempC > 0)
            {
                var cpuColor = snap.CpuTempC > 85 ? AccentRed : snap.CpuTempC > 70 ? AccentOrange : AccentGreen;
                using var cpuBrush = new SolidBrush(cpuColor);
                g.DrawString($"{snap.CpuTempC:F0}", valueFont, cpuBrush, x, y);

                using var degFont = new Font("Segoe UI", 10);
                var numW = g.MeasureString($"{snap.CpuTempC:F0}", valueFont).Width;
                g.DrawString(" C", degFont, mutedBrush, x + numW, y + 8);

                y += 34;
                if (!string.IsNullOrEmpty(snap.CpuTempSource))
                    g.DrawString(snap.CpuTempSource, detailFont, mutedBrush, x, y);
            }
            else
            {
                g.DrawString("N/A", valueFont, mutedBrush, x, y);
                y += 34;
                g.DrawString("Install LibreHardwareMonitor for temps", detailFont, mutedBrush, x, y);
            }

            // GPU Temperature (right side)
            var rx = bounds.X + bounds.Width / 2 + 10;
            var ry = bounds.Y + 12;

            g.DrawString("GPU", labelFont, subBrush, rx, ry);
            ry += 18;

            if (snap.GpuTempC > 0)
            {
                var gpuColor = snap.GpuTempC > 85 ? AccentRed : snap.GpuTempC > 70 ? AccentOrange : AccentGreen;
                using var gpuBrush = new SolidBrush(gpuColor);
                g.DrawString($"{snap.GpuTempC:F0}", valueFont, gpuBrush, rx, ry);

                using var degFont = new Font("Segoe UI", 10);
                var numW = g.MeasureString($"{snap.GpuTempC:F0}", valueFont).Width;
                g.DrawString(" C", degFont, mutedBrush, rx + numW, ry + 8);

                ry += 34;
                if (!string.IsNullOrEmpty(snap.GpuTempSource))
                    g.DrawString(snap.GpuTempSource, detailFont, mutedBrush, rx, ry);
            }
            else
            {
                g.DrawString("N/A", valueFont, mutedBrush, rx, ry);
                ry += 34;
                g.DrawString("No GPU sensor detected", detailFont, mutedBrush, rx, ry);
            }

            // Temperature guide at bottom
            var by = bounds.Bottom - 24;
            using var guideFont = new Font("Segoe UI", 7);
            using var greenBrush = new SolidBrush(AccentGreen);
            using var orangeBrush = new SolidBrush(AccentOrange);
            using var redBrush = new SolidBrush(AccentRed);

            g.FillRectangle(greenBrush, x, by + 2, 8, 8);
            g.DrawString("<70 C Normal", guideFont, mutedBrush, x + 12, by);

            g.FillRectangle(orangeBrush, x + 100, by + 2, 8, 8);
            g.DrawString("70-85 C Warm", guideFont, mutedBrush, x + 112, by);

            g.FillRectangle(redBrush, x + 210, by + 2, 8, 8);
            g.DrawString(">85 C Hot!", guideFont, mutedBrush, x + 222, by);
        }

        private void PaintNetworkCard(Graphics g, Rectangle bounds, HealthSnapshot snap)
        {
            var x = bounds.X + 16;
            var y = bounds.Y + 12;

            using var labelFont = new Font("Segoe UI", 9, FontStyle.Bold);
            using var valueFont = new Font("Segoe UI", 14, FontStyle.Bold);
            using var detailFont = new Font("Segoe UI", 8);
            using var textBrush = new SolidBrush(TextPrimary);
            using var subBrush = new SolidBrush(TextSecondary);

            // Upload
            using var upBrush = new SolidBrush(AccentGreen);
            g.DrawString("Upload", labelFont, subBrush, x, y);
            y += 18;
            var upText = FormatSpeed(snap.NetworkSentKBps);
            g.DrawString(upText, valueFont, upBrush, x, y);

            // Download
            y += 26;
            using var downBrush = new SolidBrush(AccentCyan);
            g.DrawString("Download", labelFont, subBrush, x, y);
            y += 18;
            var downText = FormatSpeed(snap.NetworkRecvKBps);
            g.DrawString(downText, valueFont, downBrush, x, y);

            // Sparklines on right side
            var sparkX = bounds.X + bounds.Width / 2 + 10;
            var sparkW = bounds.Right - sparkX - 16;

            if (_netSendHistory.Count > 2)
            {
                DrawSparkline(g, sparkX, bounds.Y + 16, sparkW, 45, _netSendHistory.ToArray(), AccentGreen);
                DrawSparkline(g, sparkX, bounds.Y + 74, sparkW, 45, _netRecvHistory.ToArray(), AccentCyan);
            }
        }

        private void PaintSecurityCard(Graphics g, Rectangle bounds)
        {
            var cx = bounds.X + 70;
            var cy = bounds.Y + 72;

            if (_securityScanner == null)
            {
                using var loadFont = new Font("Segoe UI", 10);
                using var loadBrush = new SolidBrush(TextSecondary);
                g.DrawString("Scanning...", loadFont, loadBrush, bounds.X + 16, bounds.Y + 60);
                return;
            }

            var score = _securityScanner.TotalScore;
            var grade = _securityScanner.Grade;
            var radius = 45;

            // Arc gauge
            using var bgPen = new Pen(Color.FromArgb(40, 45, 60), 8);
            g.DrawArc(bgPen, cx - radius, cy - radius, radius * 2, radius * 2, 135, 270);

            var sweepAngle = score / 100f * 270f;
            var color = score >= 80 ? AccentGreen : score >= 60 ? AccentYellow : AccentRed;
            using var valuePen = new Pen(color, 8);
            valuePen.StartCap = LineCap.Round;
            valuePen.EndCap = LineCap.Round;
            g.DrawArc(valuePen, cx - radius, cy - radius, radius * 2, radius * 2, 135, sweepAngle);

            // Score + Grade
            using var scoreFont = new Font("Segoe UI", 20, FontStyle.Bold);
            using var scoreBrush = new SolidBrush(color);
            var stxt = score.ToString();
            var ssz = g.MeasureString(stxt, scoreFont);
            g.DrawString(stxt, scoreFont, scoreBrush, cx - ssz.Width / 2, cy - ssz.Height / 2 - 6);

            using var gradeFont = new Font("Segoe UI", 8, FontStyle.Bold);
            using var mutedBrush = new SolidBrush(TextMuted);
            var gsz = g.MeasureString($"Grade: {grade}", gradeFont);
            g.DrawString($"Grade: {grade}", gradeFont, mutedBrush, cx - gsz.Width / 2, cy + ssz.Height / 2 - 10);

            // Issues list on right
            var rx = bounds.X + 150;
            var ry = bounds.Y + 12;
            using var itemFont = new Font("Segoe UI", 8);
            using var passFont = new Font("Segoe UI", 8, FontStyle.Bold);
            using var passBrush = new SolidBrush(AccentGreen);
            using var failBrush = new SolidBrush(AccentRed);
            using var textBrush = new SolidBrush(TextSecondary);

            var failedChecks = _securityScanner.Checks.Where(c => !c.Passed).ToList();
            var passedCount = _securityScanner.Checks.Count(c => c.Passed);

            g.DrawString($"{passedCount}/{_securityScanner.Checks.Count} checks passed", itemFont, textBrush, rx, ry);
            ry += 18;

            if (failedChecks.Count == 0)
            {
                g.DrawString("All security checks passed!", passFont, passBrush, rx, ry);
            }
            else
            {
                g.DrawString("Issues found:", itemFont, failBrush, rx, ry);
                ry += 16;

                foreach (var check in failedChecks.Take(5))
                {
                    g.FillEllipse(failBrush, rx, ry + 4, 6, 6);
                    g.DrawString(check.Name, itemFont, textBrush, rx + 12, ry);
                    ry += 15;
                }

                if (failedChecks.Count > 5)
                {
                    g.DrawString($"+{failedChecks.Count - 5} more...", itemFont, mutedBrush, rx + 12, ry);
                }
            }

            // Rescan button hint
            using var hintFont = new Font("Segoe UI", 7);
            g.DrawString("Click to view full report", hintFont, mutedBrush,
                bounds.X + 16, bounds.Bottom - 18);
        }

        private void PaintProcessCard(Graphics g, Rectangle bounds, HealthSnapshot snap)
        {
            var x = bounds.X + 16;
            var y = bounds.Y + 10;

            using var headerFont = new Font("Segoe UI", 8, FontStyle.Bold);
            using var itemFont = new Font("Segoe UI", 8);
            using var textBrush = new SolidBrush(TextPrimary);
            using var subBrush = new SolidBrush(TextSecondary);
            using var mutedBrush = new SolidBrush(TextMuted);

            // Header row
            g.DrawString("Process", headerFont, subBrush, x, y);
            g.DrawString("Memory", headerFont, subBrush, bounds.Right - 90, y);
            y += 18;

            // Divider
            using var divPen = new Pen(Color.FromArgb(40, 45, 60), 1);
            g.DrawLine(divPen, x, y, bounds.Right - 16, y);
            y += 4;

            foreach (var proc in snap.TopProcesses.Take(6))
            {
                var name = proc.Name.Length > 28 ? proc.Name.Substring(0, 25) + "..." : proc.Name;
                g.DrawString(name, itemFont, textBrush, x, y);

                var memText = proc.MemoryMB >= 1024
                    ? $"{proc.MemoryMB / 1024:F1} GB"
                    : $"{proc.MemoryMB:F0} MB";
                var msz = g.MeasureString(memText, itemFont);
                g.DrawString(memText, itemFont, subBrush, bounds.Right - msz.Width - 20, y);
                y += 17;
            }

            // Process count at bottom
            using var countFont = new Font("Segoe UI", 7);
            g.DrawString($"{snap.ProcessCount} processes running", countFont, mutedBrush,
                x, bounds.Bottom - 18);
        }

        private void PaintSystemInfoCard(Graphics g, Rectangle bounds, HealthSnapshot snap)
        {
            var x = bounds.X + 16;
            var y = bounds.Y + 12;

            using var labelFont = new Font("Segoe UI", 8);
            using var valueFont = new Font("Segoe UI", 8.5f, FontStyle.Bold);
            using var textBrush = new SolidBrush(TextPrimary);
            using var subBrush = new SolidBrush(TextSecondary);

            var items = new[]
            {
                ("Computer", SystemInfo.GetHostname()),
                ("User", SystemInfo.GetUsername()),
                ("Uptime", FormatUptime(snap.Uptime)),
                ("OS", TruncateText(SystemInfo.GetOSVersion(), 40)),
                ("CPU", TruncateText(SystemInfo.GetCPU(), 40)),
                ("IP", SystemInfo.GetIPAddress())
            };

            foreach (var (label, value) in items)
            {
                g.DrawString(label + ":", labelFont, subBrush, x, y);
                g.DrawString(value, valueFont, textBrush, x + 70, y);
                y += 18;
            }
        }

        // --- Drawing Helpers ---

        private void DrawSparkline(Graphics g, float x, float y, float w, float h,
            float[] data, Color color)
        {
            if (data.Length < 2 || w < 10 || h < 10) return;

            var maxVal = data.Max();
            if (maxVal < 1) maxVal = 1;

            var points = new PointF[data.Length];
            for (int i = 0; i < data.Length; i++)
            {
                var px = x + (i / (float)(data.Length - 1)) * w;
                var py = y + h - (data[i] / maxVal * h);
                points[i] = new PointF(px, py);
            }

            // Fill area under curve
            var fillPoints = new List<PointF>(points);
            fillPoints.Add(new PointF(x + w, y + h));
            fillPoints.Add(new PointF(x, y + h));
            using var fillBrush = new SolidBrush(Color.FromArgb(30, color));
            g.FillPolygon(fillBrush, fillPoints.ToArray());

            // Draw line
            using var pen = new Pen(Color.FromArgb(180, color), 1.5f);
            pen.LineJoin = LineJoin.Round;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.DrawLines(pen, points);
        }

        private static string FormatSpeed(float kbps)
        {
            if (kbps >= 1024)
                return $"{kbps / 1024:F1} MB/s";
            return $"{kbps:F0} KB/s";
        }

        private static string FormatUptime(TimeSpan ts)
        {
            if (ts.TotalDays >= 1)
                return $"{ts.Days}d {ts.Hours}h {ts.Minutes}m";
            return $"{ts.Hours}h {ts.Minutes}m {ts.Seconds}s";
        }

        private static string TruncateText(string text, int maxLen)
        {
            if (text.Length <= maxLen) return text;
            return text.Substring(0, maxLen - 3) + "...";
        }

        private static string GetVersion()
        {
            var asm = System.Reflection.Assembly.GetExecutingAssembly();
            var ver = asm.GetName().Version;
            return ver != null ? $"{ver.Major}.{ver.Minor}.{ver.Build}" : "0.0.0";
        }

        private static GraphicsPath CreateRoundRect(Rectangle bounds, int radius)
        {
            var path = new GraphicsPath();
            var d = radius * 2;
            path.AddArc(bounds.X, bounds.Y, d, d, 180, 90);
            path.AddArc(bounds.Right - d, bounds.Y, d, d, 270, 90);
            path.AddArc(bounds.Right - d, bounds.Bottom - d, d, d, 0, 90);
            path.AddArc(bounds.X, bounds.Bottom - d, d, d, 90, 90);
            path.CloseFigure();
            return path;
        }
    }

    /// <summary>
    /// Custom double-buffered panel with rounded corners and dark card styling.
    /// </summary>
    public class DashboardPanel : Panel
    {
        public string Title { get; set; } = "";
        public event Action<Graphics, Rectangle>? CustomPaint;

        public DashboardPanel()
        {
            DoubleBuffered = true;
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint |
                     ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
            BackColor = Color.Transparent;
            Cursor = Cursors.Hand;
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.TextRenderingHint = TextRenderingHint.ClearTypeGridFit;

            var cardRect = new Rectangle(0, 0, Width - 1, Height - 1);

            // Card background with rounded corners
            using var cardPath = CreateRoundRect(cardRect, 10);
            using var cardBrush = new SolidBrush(Color.FromArgb(28, 30, 40));
            g.FillPath(cardBrush, cardPath);

            // Subtle border
            using var borderPen = new Pen(Color.FromArgb(45, 50, 65), 1);
            g.DrawPath(borderPen, cardPath);

            // Title
            if (!string.IsNullOrEmpty(Title))
            {
                // Title is drawn by the custom paint handler as part of the card content
                // But we draw a subtle top accent
            }

            // Custom content painting
            var contentBounds = new Rectangle(4, 4, Width - 8, Height - 8);
            CustomPaint?.Invoke(g, contentBounds);
        }

        private static GraphicsPath CreateRoundRect(Rectangle bounds, int radius)
        {
            var path = new GraphicsPath();
            var d = radius * 2;
            path.AddArc(bounds.X, bounds.Y, d, d, 180, 90);
            path.AddArc(bounds.Right - d, bounds.Y, d, d, 270, 90);
            path.AddArc(bounds.Right - d, bounds.Bottom - d, d, d, 0, 90);
            path.AddArc(bounds.X, bounds.Bottom - d, d, d, 90, 90);
            path.CloseFigure();
            return path;
        }
    }
}
