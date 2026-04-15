using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Text;
using System.Linq;
using System.Windows.Forms;

namespace SupportTray
{
    /// <summary>
    /// Detailed security report form showing all checks with pass/fail and recommendations.
    /// </summary>
    public class SecurityReportForm : Form
    {
        private readonly SecurityScanner _scanner;
        private readonly AppConfig _config;

        public SecurityReportForm(AppConfig config, SecurityScanner scanner)
        {
            _config = config;
            _scanner = scanner;
            InitializeUI();
        }

        private void InitializeUI()
        {
            Text = $"{_config.CompanyName} - Security Report";
            Size = new Size(620, 700);
            StartPosition = FormStartPosition.CenterScreen;
            BackColor = Color.FromArgb(18, 18, 24);
            Font = new Font("Segoe UI", 9.5f);
            DoubleBuffered = true;

            // Header
            var header = new Panel
            {
                Dock = DockStyle.Top,
                Height = 80,
                BackColor = Color.FromArgb(22, 24, 32)
            };
            header.Paint += (s, e) =>
            {
                var g = e.Graphics;
                g.TextRenderingHint = TextRenderingHint.ClearTypeGridFit;

                var score = _scanner.TotalScore;
                var color = score >= 80 ? Color.FromArgb(34, 197, 94) :
                            score >= 60 ? Color.FromArgb(250, 204, 21) :
                            Color.FromArgb(239, 68, 68);

                using var titleFont = new Font("Segoe UI", 16, FontStyle.Bold);
                using var whiteBrush = new SolidBrush(Color.White);
                g.DrawString("Security Report", titleFont, whiteBrush, 20, 12);

                using var scoreFont = new Font("Segoe UI", 24, FontStyle.Bold);
                using var scoreBrush = new SolidBrush(color);
                var scoreTxt = $"{score}/100";
                var ssz = g.MeasureString(scoreTxt, scoreFont);
                g.DrawString(scoreTxt, scoreFont, scoreBrush, header.Width - ssz.Width - 20, 8);

                using var gradeFont = new Font("Segoe UI", 12, FontStyle.Bold);
                var gradeTxt = $"Grade: {_scanner.Grade}";
                var gsz = g.MeasureString(gradeTxt, gradeFont);
                g.DrawString(gradeTxt, gradeFont, scoreBrush, header.Width - gsz.Width - 20, 48);

                using var subFont = new Font("Segoe UI", 9);
                using var subBrush = new SolidBrush(Color.FromArgb(148, 163, 184));
                g.DrawString($"Scanned: {_scanner.LastScan:yyyy-MM-dd HH:mm}", subFont, subBrush, 20, 48);
            };
            Controls.Add(header);

            // Scrollable checks list
            var listPanel = new Panel
            {
                Dock = DockStyle.Fill,
                AutoScroll = true,
                BackColor = Color.FromArgb(18, 18, 24),
                Padding = new Padding(16, 8, 16, 8)
            };

            int y = 8;
            foreach (var check in _scanner.Checks)
            {
                var checkPanel = new CheckItemPanel(check)
                {
                    Location = new Point(8, y),
                    Size = new Size(560, check.Passed ? 50 : 75)
                };
                listPanel.Controls.Add(checkPanel);
                y += checkPanel.Height + 8;
            }

            Controls.Add(listPanel);
            listPanel.BringToFront();

            // Bottom bar with buttons
            var bottomBar = new Panel
            {
                Dock = DockStyle.Bottom,
                Height = 50,
                BackColor = Color.FromArgb(22, 24, 32)
            };

            var copyBtn = new Button
            {
                Text = "Copy Report",
                Size = new Size(110, 34),
                Location = new Point(16, 8),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(59, 130, 246),
                ForeColor = Color.White,
                Cursor = Cursors.Hand
            };
            copyBtn.FlatAppearance.BorderSize = 0;
            copyBtn.Click += (s, e) =>
            {
                Clipboard.SetText(_scanner.GetReportText());
                MessageBox.Show("Security report copied to clipboard.", "Copied",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
            };
            bottomBar.Controls.Add(copyBtn);

            var rescanBtn = new Button
            {
                Text = "Rescan",
                Size = new Size(90, 34),
                Location = new Point(136, 8),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(40, 45, 60),
                ForeColor = Color.White,
                Cursor = Cursors.Hand
            };
            rescanBtn.FlatAppearance.BorderSize = 0;
            rescanBtn.Click += (s, e) =>
            {
                rescanBtn.Enabled = false;
                rescanBtn.Text = "Scanning...";
                System.Threading.Tasks.Task.Run(() =>
                {
                    _scanner.RunFullScan();
                    if (!IsDisposed)
                    {
                        Invoke(() =>
                        {
                            // Rebuild the form
                            Controls.Clear();
                            InitializeUI();
                        });
                    }
                });
            };
            bottomBar.Controls.Add(rescanBtn);

            var closeBtn = new Button
            {
                Text = "Close",
                Size = new Size(80, 34),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(40, 45, 60),
                ForeColor = Color.White,
                Cursor = Cursors.Hand
            };
            closeBtn.FlatAppearance.BorderSize = 0;
            closeBtn.Click += (s, e) => Close();
            bottomBar.Controls.Add(closeBtn);

            bottomBar.Resize += (s, e) =>
            {
                closeBtn.Location = new Point(bottomBar.Width - closeBtn.Width - 16, 8);
            };

            Controls.Add(bottomBar);
        }

        private class CheckItemPanel : Panel
        {
            private readonly SecurityCheck _check;

            public CheckItemPanel(SecurityCheck check)
            {
                _check = check;
                DoubleBuffered = true;
                SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint |
                         ControlStyles.OptimizedDoubleBuffer, true);
            }

            protected override void OnPaint(PaintEventArgs e)
            {
                var g = e.Graphics;
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.TextRenderingHint = TextRenderingHint.ClearTypeGridFit;

                var bgColor = Color.FromArgb(28, 30, 40);
                using var bgBrush = new SolidBrush(bgColor);
                using var bgPath = CreateRoundRect(new Rectangle(0, 0, Width - 1, Height - 1), 8);
                g.FillPath(bgBrush, bgPath);

                // Status indicator
                var statusColor = _check.Passed
                    ? Color.FromArgb(34, 197, 94)
                    : Color.FromArgb(239, 68, 68);
                using var statusBrush = new SolidBrush(statusColor);
                g.FillEllipse(statusBrush, 14, 16, 14, 14);

                // Check mark or X
                using var symbolFont = new Font("Segoe UI", 8, FontStyle.Bold);
                using var whiteBrush = new SolidBrush(Color.White);
                var symbol = _check.Passed ? "\u2713" : "\u2717";
                g.DrawString(symbol, symbolFont, whiteBrush, 16, 15);

                // Name
                using var nameFont = new Font("Segoe UI", 10, FontStyle.Bold);
                using var textBrush = new SolidBrush(Color.FromArgb(240, 240, 250));
                g.DrawString(_check.Name, nameFont, textBrush, 38, 8);

                // Weight badge
                using var badgeFont = new Font("Segoe UI", 7, FontStyle.Bold);
                var badgeText = $"{_check.Weight} pts";
                var bsz = g.MeasureString(badgeText, badgeFont);
                var bx = Width - bsz.Width - 20;
                using var badgeBg = new SolidBrush(Color.FromArgb(40, 45, 60));
                g.FillRectangle(badgeBg, bx - 4, 10, bsz.Width + 8, 18);
                using var badgeBrush = new SolidBrush(Color.FromArgb(148, 163, 184));
                g.DrawString(badgeText, badgeFont, badgeBrush, bx, 11);

                // Detail
                using var detailFont = new Font("Segoe UI", 8.5f);
                using var detailBrush = new SolidBrush(Color.FromArgb(148, 163, 184));
                g.DrawString(_check.Detail, detailFont, detailBrush, 38, 30);

                // Recommendation (for failed checks)
                if (!_check.Passed && !string.IsNullOrEmpty(_check.Recommendation))
                {
                    using var fixFont = new Font("Segoe UI", 8);
                    using var fixBrush = new SolidBrush(Color.FromArgb(250, 204, 21));
                    g.DrawString("Fix: " + _check.Recommendation, fixFont, fixBrush, 38, 50);
                }
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
}
