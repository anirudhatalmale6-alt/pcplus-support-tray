using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;
using PCPlus.Core.IPC;
using PCPlus.Core.Models;

namespace PCPlus.Tray.Forms
{
    /// <summary>
    /// Security Report - shows security scan results with pass/fail checks.
    /// </summary>
    public class SecurityReportForm : Form
    {
        private readonly IpcClient _ipc;
        private static readonly Color BgDark = Color.FromArgb(18, 18, 24);
        private static readonly Color BgCard = Color.FromArgb(28, 28, 40);
        private static readonly Color TextPrimary = Color.FromArgb(230, 230, 240);
        private static readonly Color TextSecondary = Color.FromArgb(140, 140, 160);
        private static readonly Color Green = Color.FromArgb(34, 197, 94);
        private static readonly Color Red = Color.FromArgb(239, 68, 68);
        private static readonly Color Orange = Color.FromArgb(245, 158, 11);
        private static readonly Color Border = Color.FromArgb(45, 45, 60);

        private Panel _scorePanel = null!;
        private Panel _checksPanel = null!;
        private Button _rescanButton = null!;
        private Label _statusLabel = null!;

        public SecurityReportForm(IpcClient ipc)
        {
            _ipc = ipc;
            InitializeForm();
            BuildUI();
            _ = LoadReport();
        }

        private void InitializeForm()
        {
            Text = "PC Plus - Security Report";
            Size = new Size(650, 550);
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
            var header = new Panel { Dock = DockStyle.Top, Height = 55, BackColor = BgCard };
            var title = new Label
            {
                Text = "Security Report", AutoSize = true,
                Font = new Font("Segoe UI", 14, FontStyle.Bold),
                ForeColor = TextPrimary, Location = new Point(16, 12)
            };
            _rescanButton = new Button
            {
                Text = "Run Scan", Size = new Size(100, 32),
                FlatStyle = FlatStyle.Flat, BackColor = Color.FromArgb(60, 130, 246),
                ForeColor = Color.White, Font = new Font("Segoe UI", 9, FontStyle.Bold),
                Cursor = Cursors.Hand, Anchor = AnchorStyles.Top | AnchorStyles.Right,
                Location = new Point(530, 10)
            };
            _rescanButton.FlatAppearance.BorderSize = 0;
            _rescanButton.Click += async (s, e) =>
            {
                _rescanButton.Enabled = false;
                _rescanButton.Text = "Scanning...";
                await Task.Run(() => _ipc.RunSecurityScanAsync());
                await Task.Delay(3000);
                await LoadReport();
                _rescanButton.Enabled = true;
                _rescanButton.Text = "Run Scan";
            };
            header.Controls.AddRange(new Control[] { title, _rescanButton });

            // Score panel (big score display)
            _scorePanel = new Panel
            {
                Location = new Point(16, 65), Size = new Size(600, 80),
                BackColor = BgCard
            };
            _scorePanel.Paint += (s, e) =>
            {
                using var pen = new Pen(Border);
                e.Graphics.DrawRectangle(pen, 0, 0, _scorePanel.Width - 1, _scorePanel.Height - 1);
            };

            // Checks list (scrollable)
            _checksPanel = new Panel
            {
                Location = new Point(16, 155), Size = new Size(600, 330),
                BackColor = BgCard, AutoScroll = true
            };
            _checksPanel.Paint += (s, e) =>
            {
                using var pen = new Pen(Border);
                e.Graphics.DrawRectangle(pen, 0, 0, _checksPanel.Width - 1, _checksPanel.Height - 1);
            };

            _statusLabel = new Label
            {
                Text = "Loading...", Location = new Point(16, 155),
                AutoSize = true, ForeColor = TextSecondary
            };

            Controls.AddRange(new Control[] { header, _scorePanel, _checksPanel, _statusLabel });
        }

        private async Task LoadReport()
        {
            try
            {
                _statusLabel.Text = "Loading security report...";
                var response = await Task.Run(() => _ipc.GetSecurityScoreAsync());
                if (response.Success)
                {
                    var result = response.GetData<SecurityScanResult>();
                    if (result != null)
                    {
                        if (InvokeRequired)
                            Invoke(new Action(() => DisplayReport(result)));
                        else
                            DisplayReport(result);
                    }
                }
                else
                {
                    _statusLabel.Text = "Could not load report. Service may not be connected.";
                }
            }
            catch
            {
                _statusLabel.Text = "Error loading security report.";
            }
        }

        private void DisplayReport(SecurityScanResult result)
        {
            _statusLabel.Text = "";

            // Score display
            _scorePanel.Controls.Clear();
            var gradeColor = result.Grade switch
            {
                "A" => Green, "B" => Color.FromArgb(96, 165, 250),
                "C" => Orange, _ => Red
            };

            var gradeLabel = new Label
            {
                Text = result.Grade, Font = new Font("Segoe UI", 32, FontStyle.Bold),
                ForeColor = gradeColor, BackColor = Color.Transparent,
                Location = new Point(20, 10), AutoSize = true
            };
            var scoreLabel = new Label
            {
                Text = $"{result.TotalScore} / 100", Font = new Font("Segoe UI", 18),
                ForeColor = TextPrimary, BackColor = Color.Transparent,
                Location = new Point(80, 22), AutoSize = true
            };
            var passedCount = result.Checks.Count(c => c.Passed);
            var summaryLabel = new Label
            {
                Text = $"{passedCount} of {result.Checks.Count} checks passed     Scanned: {result.ScanTime:HH:mm:ss}",
                Font = new Font("Segoe UI", 9),
                ForeColor = TextSecondary, BackColor = Color.Transparent,
                Location = new Point(220, 30), AutoSize = true
            };
            _scorePanel.Controls.AddRange(new Control[] { gradeLabel, scoreLabel, summaryLabel });

            // Checks list
            _checksPanel.Controls.Clear();
            int y = 8;
            foreach (var check in result.Checks.OrderBy(c => c.Passed).ThenBy(c => c.Category))
            {
                var checkPanel = new Panel
                {
                    Location = new Point(8, y), Size = new Size(565, 48),
                    BackColor = BgCard
                };
                checkPanel.Paint += (s, e) =>
                {
                    using var pen = new Pen(Border);
                    e.Graphics.DrawLine(pen, 0, checkPanel.Height - 1, checkPanel.Width, checkPanel.Height - 1);
                };

                var icon = new Label
                {
                    Text = check.Passed ? "\u2713" : "\u2717",
                    Font = new Font("Segoe UI", 12, FontStyle.Bold),
                    ForeColor = check.Passed ? Green : Red,
                    BackColor = Color.Transparent,
                    Location = new Point(8, 10), AutoSize = true
                };

                var nameLabel = new Label
                {
                    Text = check.Name,
                    Font = new Font("Segoe UI", 9.5f, check.Passed ? FontStyle.Regular : FontStyle.Bold),
                    ForeColor = TextPrimary, BackColor = Color.Transparent,
                    Location = new Point(35, 4), AutoSize = true
                };

                var detailLabel = new Label
                {
                    Text = check.Passed ? check.Detail : (check.Recommendation ?? check.Detail),
                    Font = new Font("Segoe UI", 8),
                    ForeColor = check.Passed ? TextSecondary : Orange,
                    BackColor = Color.Transparent,
                    Location = new Point(35, 24), AutoSize = true,
                    MaximumSize = new Size(500, 0)
                };

                var catLabel = new Label
                {
                    Text = check.Category, Font = new Font("Segoe UI", 7.5f),
                    ForeColor = TextSecondary, BackColor = Color.Transparent,
                    Location = new Point(490, 8), AutoSize = true
                };

                checkPanel.Controls.AddRange(new Control[] { icon, nameLabel, detailLabel, catLabel });
                _checksPanel.Controls.Add(checkPanel);
                y += 52;
            }
        }
    }
}
