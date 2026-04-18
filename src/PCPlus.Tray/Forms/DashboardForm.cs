using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;
using PCPlus.Core.IPC;
using PCPlus.Core.Models;

namespace PCPlus.Tray.Forms
{
    /// <summary>
    /// Health Dashboard - shows real-time system health with gauges and details.
    /// Dark themed to match the web dashboard.
    /// </summary>
    public class DashboardForm : Form
    {
        private readonly IpcClient _ipc;
        private readonly System.Windows.Forms.Timer _refreshTimer;

        // Colors
        private static readonly Color BgDark = Color.FromArgb(18, 18, 24);
        private static readonly Color BgCard = Color.FromArgb(28, 28, 40);
        private static readonly Color BgCardHover = Color.FromArgb(35, 35, 50);
        private static readonly Color TextPrimary = Color.FromArgb(230, 230, 240);
        private static readonly Color TextSecondary = Color.FromArgb(140, 140, 160);
        private static readonly Color AccentBlue = Color.FromArgb(60, 130, 246);
        private static readonly Color AccentGreen = Color.FromArgb(34, 197, 94);
        private static readonly Color AccentOrange = Color.FromArgb(245, 158, 11);
        private static readonly Color AccentRed = Color.FromArgb(239, 68, 68);
        private static readonly Color Border = Color.FromArgb(45, 45, 60);

        // Data
        private HealthSnapshot? _health;
        private ServiceStatusReport? _serviceStatus;

        // UI Controls
        private Panel _headerPanel = null!;
        private Panel _contentPanel = null!;
        private Label _statusLabel = null!;
        private Label _uptimeLabel = null!;

        // Gauge panels
        private GaugePanel _cpuGauge = null!;
        private GaugePanel _ramGauge = null!;
        private GaugePanel _diskGauge = null!;
        private GaugePanel _cpuTempGauge = null!;

        // Info panels
        private Panel _processPanel = null!;
        private Panel _diskDetailPanel = null!;
        private Panel _networkPanel = null!;

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
            Text = "PC Plus - Health Dashboard";
            Size = new Size(820, 620);
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
            // Header
            _headerPanel = new Panel
            {
                Dock = DockStyle.Top, Height = 60, BackColor = BgCard,
                Padding = new Padding(16, 0, 16, 0)
            };
            var titleLabel = new Label
            {
                Text = "Health Dashboard", AutoSize = true,
                Font = new Font("Segoe UI", 14, FontStyle.Bold),
                ForeColor = TextPrimary, Location = new Point(16, 8)
            };
            _statusLabel = new Label
            {
                Text = "Connecting...", AutoSize = true,
                Font = new Font("Segoe UI", 9),
                ForeColor = AccentBlue, Location = new Point(16, 35)
            };
            _uptimeLabel = new Label
            {
                Text = "", AutoSize = true,
                Font = new Font("Segoe UI", 9),
                ForeColor = TextSecondary, Anchor = AnchorStyles.Top | AnchorStyles.Right
            };
            _uptimeLabel.Location = new Point(_headerPanel.Width - 200, 20);
            _headerPanel.Controls.AddRange(new Control[] { titleLabel, _statusLabel, _uptimeLabel });

            // Content area with scroll
            _contentPanel = new Panel
            {
                Dock = DockStyle.Fill, AutoScroll = true,
                BackColor = BgDark, Padding = new Padding(16)
            };

            // Gauge row
            var gaugeRow = new FlowLayoutPanel
            {
                FlowDirection = FlowDirection.LeftToRight,
                WrapContents = false, AutoSize = true,
                Location = new Point(16, 8), BackColor = Color.Transparent
            };

            _cpuGauge = new GaugePanel("CPU", "%", AccentBlue) { Size = new Size(180, 160) };
            _ramGauge = new GaugePanel("RAM", "%", AccentGreen) { Size = new Size(180, 160) };
            _diskGauge = new GaugePanel("Disk", "%", AccentOrange) { Size = new Size(180, 160) };
            _cpuTempGauge = new GaugePanel("CPU Temp", "°C", AccentRed) { Size = new Size(180, 160) };

            gaugeRow.Controls.AddRange(new Control[] { _cpuGauge, _ramGauge, _diskGauge, _cpuTempGauge });

            // Details section
            _processPanel = CreateDetailPanel("Top Processes", new Point(16, 180), new Size(375, 220));
            _diskDetailPanel = CreateDetailPanel("Disk Usage", new Point(407, 180), new Size(375, 95));
            _networkPanel = CreateDetailPanel("System Info", new Point(407, 285), new Size(375, 95));

            _contentPanel.Controls.AddRange(new Control[] { gaugeRow, _processPanel, _diskDetailPanel, _networkPanel });

            Controls.Add(_contentPanel);
            Controls.Add(_headerPanel);
        }

        private Panel CreateDetailPanel(string title, Point location, Size size)
        {
            var panel = new Panel
            {
                Location = location, Size = size,
                BackColor = BgCard, Padding = new Padding(12)
            };
            panel.Paint += (s, e) =>
            {
                using var pen = new Pen(Border);
                e.Graphics.DrawRectangle(pen, 0, 0, panel.Width - 1, panel.Height - 1);
            };

            var titleLabel = new Label
            {
                Text = title, AutoSize = true, Location = new Point(12, 8),
                Font = new Font("Segoe UI", 10, FontStyle.Bold),
                ForeColor = TextPrimary, BackColor = Color.Transparent
            };
            panel.Controls.Add(titleLabel);
            panel.Tag = titleLabel; // We'll add content below the title
            return panel;
        }

        private async Task RefreshData()
        {
            try
            {
                // Try to connect if not connected
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
                            _statusLabel.Text = "Service not connected - retrying...";
                            _statusLabel.ForeColor = AccentOrange;
                        }));
                    return;
                }

                var healthResponse = await Task.Run(() => _ipc.GetHealthSnapshotAsync());
                if (healthResponse.Success)
                {
                    _health = healthResponse.GetData<HealthSnapshot>();
                    if (_health != null)
                        UpdateGauges();
                }
                else
                {
                    if (InvokeRequired)
                        Invoke(new Action(() =>
                        {
                            _statusLabel.Text = $"Connected - waiting for data ({healthResponse.Message})";
                            _statusLabel.ForeColor = AccentBlue;
                        }));
                }

                var statusResponse = await Task.Run(() => _ipc.GetServiceStatusAsync());
                if (statusResponse.Success)
                {
                    _serviceStatus = statusResponse.GetData<ServiceStatusReport>();
                    UpdateStatus();
                }
            }
            catch { }
        }

        private void UpdateGauges()
        {
            if (_health == null) return;
            if (InvokeRequired) { Invoke(new Action(UpdateGauges)); return; }

            _cpuGauge.SetValue(_health.CpuPercent, 100);
            _ramGauge.SetValue(_health.RamPercent, 100,
                $"{_health.RamUsedGB:F1} / {_health.RamTotalGB:F1} GB");
            var disk = _health.Disks.FirstOrDefault();
            _diskGauge.SetValue(disk?.UsedPercent ?? 0, 100,
                disk != null ? $"{disk.TotalGB - disk.FreeGB:F0} / {disk.TotalGB:F0} GB" : "");
            _cpuTempGauge.SetValue(_health.CpuTempC, 100,
                _health.CpuTempC > 0 ? "" : "No sensor");

            // Update uptime
            if (_health.Uptime.TotalMinutes > 0)
            {
                var up = _health.Uptime;
                _uptimeLabel.Text = $"Uptime: {(int)up.TotalDays}d {up.Hours}h {up.Minutes}m";
            }

            // Update process list
            UpdateProcessList();
            UpdateDiskDetails();
            UpdateNetworkInfo();

            _statusLabel.Text = $"Connected - {_health.ProcessCount} processes";
            _statusLabel.ForeColor = AccentGreen;
        }

        private void UpdateProcessList()
        {
            if (_health?.TopProcesses == null) return;

            // Clear old content labels (keep title)
            var toRemove = _processPanel.Controls.OfType<Label>()
                .Where(l => l != (Label)_processPanel.Tag!).ToList();
            foreach (var l in toRemove) { _processPanel.Controls.Remove(l); l.Dispose(); }

            // Header row
            int y = 30;
            var header = new Label
            {
                Text = "Name                   CPU     Memory",
                Font = new Font("Segoe UI", 8f, FontStyle.Bold),
                ForeColor = TextSecondary,
                BackColor = Color.Transparent,
                Location = new Point(12, y), AutoSize = true
            };
            _processPanel.Controls.Add(header);
            y += 18;

            foreach (var proc in _health.TopProcesses.Take(7))
            {
                var name = proc.Name.Length > 20 ? proc.Name.Substring(0, 20) : proc.Name;
                var line = new Label
                {
                    Text = $"{name,-22} {proc.CpuPercent,5:F1}%  {proc.MemoryMB,6:F0} MB",
                    Font = new Font("Consolas", 8.5f),
                    ForeColor = proc.CpuPercent > 50 ? AccentRed : TextSecondary,
                    BackColor = Color.Transparent,
                    Location = new Point(12, y), AutoSize = true
                };
                _processPanel.Controls.Add(line);
                y += 18;
            }
        }

        private void UpdateDiskDetails()
        {
            if (_health?.Disks == null) return;

            var toRemove = _diskDetailPanel.Controls.OfType<Label>()
                .Where(l => l != (Label)_diskDetailPanel.Tag!).ToList();
            foreach (var l in toRemove) { _diskDetailPanel.Controls.Remove(l); l.Dispose(); }

            int y = 30;
            foreach (var disk in _health.Disks.Take(3))
            {
                var color = disk.UsedPercent > 90 ? AccentRed : disk.UsedPercent > 80 ? AccentOrange : TextSecondary;
                var line = new Label
                {
                    Text = $"{disk.Name} {disk.Label,-12} {disk.FreeGB:F0} GB free / {disk.TotalGB:F0} GB ({disk.UsedPercent:F0}%)",
                    Font = new Font("Segoe UI", 9),
                    ForeColor = color, BackColor = Color.Transparent,
                    Location = new Point(12, y), AutoSize = true
                };
                _diskDetailPanel.Controls.Add(line);
                y += 20;
            }
        }

        private void UpdateNetworkInfo()
        {
            if (_health == null) return;

            var toRemove = _networkPanel.Controls.OfType<Label>()
                .Where(l => l != (Label)_networkPanel.Tag!).ToList();
            foreach (var l in toRemove) { _networkPanel.Controls.Remove(l); l.Dispose(); }

            int y = 30;
            var lines = new[]
            {
                $"Network: {_health.NetworkSentKBps:F0} KB/s up, {_health.NetworkRecvKBps:F0} KB/s down",
                $"Processes: {_health.ProcessCount}     GPU Temp: {(_health.GpuTempC > 0 ? $"{_health.GpuTempC:F0}°C" : "N/A")}"
            };

            foreach (var text in lines)
            {
                var line = new Label
                {
                    Text = text, Font = new Font("Segoe UI", 9),
                    ForeColor = TextSecondary, BackColor = Color.Transparent,
                    Location = new Point(12, y), AutoSize = true
                };
                _networkPanel.Controls.Add(line);
                y += 20;
            }
        }

        private void UpdateStatus()
        {
            // Already updated in UpdateGauges
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            _refreshTimer.Stop();
            _refreshTimer.Dispose();
            base.OnFormClosing(e);
        }
    }

    /// <summary>Circular gauge panel for displaying a metric.</summary>
    internal class GaugePanel : Panel
    {
        private float _value;
        private float _maxValue = 100;
        private string _label;
        private string _unit;
        private string _subText = "";
        private Color _accentColor;
        private readonly Font _valueFont = new("Segoe UI", 18, FontStyle.Bold);
        private readonly Font _labelFont = new("Segoe UI", 9);
        private readonly Font _subFont = new("Segoe UI", 7.5f);

        public GaugePanel(string label, string unit, Color accent)
        {
            _label = label;
            _unit = unit;
            _accentColor = accent;
            BackColor = Color.FromArgb(28, 28, 40);
            DoubleBuffered = true;
            Margin = new Padding(6);
        }

        public void SetValue(float value, float max, string? subText = null)
        {
            _value = value;
            _maxValue = max;
            if (subText != null) _subText = subText;
            Invalidate();
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

            // Background
            using var bgBrush = new SolidBrush(BackColor);
            g.FillRectangle(bgBrush, ClientRectangle);

            // Border
            using var borderPen = new Pen(Color.FromArgb(45, 45, 60));
            g.DrawRectangle(borderPen, 0, 0, Width - 1, Height - 1);

            // Arc gauge
            var arcRect = new Rectangle(30, 15, 110, 110);
            float startAngle = 135;
            float sweepAngle = 270;
            float valueSweep = _maxValue > 0 ? (_value / _maxValue) * sweepAngle : 0;

            // Background arc
            using var bgArcPen = new Pen(Color.FromArgb(40, 40, 55), 8);
            g.DrawArc(bgArcPen, arcRect, startAngle, sweepAngle);

            // Value arc
            if (valueSweep > 0)
            {
                var arcColor = _value / _maxValue > 0.9f ? Color.FromArgb(239, 68, 68) :
                    _value / _maxValue > 0.7f ? Color.FromArgb(245, 158, 11) : _accentColor;
                using var valuePen = new Pen(arcColor, 8) { StartCap = LineCap.Round, EndCap = LineCap.Round };
                g.DrawArc(valuePen, arcRect, startAngle, valueSweep);
            }

            // Value text (center of arc)
            var valueStr = _value > 0 ? $"{_value:F0}" : "-";
            var valueSize = g.MeasureString(valueStr, _valueFont);
            using var textBrush = new SolidBrush(Color.FromArgb(230, 230, 240));
            g.DrawString(valueStr, _valueFont, textBrush,
                arcRect.X + (arcRect.Width - valueSize.Width) / 2,
                arcRect.Y + (arcRect.Height - valueSize.Height) / 2 - 2);

            // Unit text
            var unitSize = g.MeasureString(_unit, _labelFont);
            using var unitBrush = new SolidBrush(Color.FromArgb(140, 140, 160));
            g.DrawString(_unit, _labelFont, unitBrush,
                arcRect.X + (arcRect.Width - unitSize.Width) / 2,
                arcRect.Y + arcRect.Height / 2 + valueSize.Height / 2 - 6);

            // Label (below gauge)
            var labelSize = g.MeasureString(_label, _labelFont);
            g.DrawString(_label, _labelFont, textBrush,
                (Width - labelSize.Width) / 2, Height - 35);

            // Sub-text
            if (!string.IsNullOrEmpty(_subText))
            {
                var subSize = g.MeasureString(_subText, _subFont);
                g.DrawString(_subText, _subFont, unitBrush,
                    (Width - subSize.Width) / 2, Height - 18);
            }
        }
    }
}
