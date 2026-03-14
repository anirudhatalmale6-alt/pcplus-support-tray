using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Text;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace SupportTray
{
    public class DesktopOverlay : Form
    {
        private Timer? _fadeTimer;
        private float _opacity = 0f;
        private bool _fadingIn = true;
        private const int SHOW_DURATION_MS = 30000; // Show for 30 seconds then fade
        private Timer? _dismissTimer;

        // Win32 for click-through and taskbar hiding
        private const int WS_EX_TOOLWINDOW = 0x00000080;
        private const int WS_EX_TOPMOST = 0x00000008;
        private const int WS_EX_NOACTIVATE = 0x08000000;

        protected override CreateParams CreateParams
        {
            get
            {
                var cp = base.CreateParams;
                cp.ExStyle |= WS_EX_TOOLWINDOW | WS_EX_TOPMOST | WS_EX_NOACTIVATE;
                return cp;
            }
        }

        public DesktopOverlay()
        {
            FormBorderStyle = FormBorderStyle.None;
            ShowInTaskbar = false;
            TopMost = true;
            StartPosition = FormStartPosition.Manual;
            BackColor = Color.Magenta;
            TransparencyKey = Color.Magenta;
            Size = new Size(320, 60);
            DoubleBuffered = true;
            Opacity = 0;

            // Position near system tray (bottom-right, above taskbar)
            var workArea = Screen.PrimaryScreen!.WorkingArea;
            Location = new Point(workArea.Right - Width - 16, workArea.Bottom - Height - 8);

            Click += (s, e) => FadeOut();

            // Fade in
            _fadeTimer = new Timer { Interval = 30 };
            _fadeTimer.Tick += FadeStep;
            _fadeTimer.Start();

            // Auto-dismiss after duration
            _dismissTimer = new Timer { Interval = SHOW_DURATION_MS };
            _dismissTimer.Tick += (s, e) =>
            {
                _dismissTimer?.Stop();
                FadeOut();
            };
        }

        private void FadeStep(object? sender, EventArgs e)
        {
            if (_fadingIn)
            {
                _opacity += 0.05f;
                if (_opacity >= 0.92f)
                {
                    _opacity = 0.92f;
                    _fadingIn = false;
                    _fadeTimer?.Stop();
                    _dismissTimer?.Start();
                }
            }
            else
            {
                _opacity -= 0.04f;
                if (_opacity <= 0)
                {
                    _opacity = 0;
                    _fadeTimer?.Stop();
                    Close();
                    return;
                }
            }
            Opacity = _opacity;
        }

        private void FadeOut()
        {
            _dismissTimer?.Stop();
            _fadingIn = false;
            if (_fadeTimer != null && !_fadeTimer.Enabled)
            {
                _fadeTimer.Start();
            }
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            base.OnPaint(e);
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.TextRenderingHint = TextRenderingHint.ClearTypeGridFit;

            var rect = new Rectangle(0, 0, Width - 1, Height - 1);

            // Rounded rectangle background
            using var path = CreateRoundedRect(rect, 12);
            using var bgBrush = new SolidBrush(Color.FromArgb(20, 30, 50));
            g.FillPath(bgBrush, path);

            // Blue accent border
            using var borderPen = new Pen(Color.FromArgb(0, 120, 212), 2f);
            g.DrawPath(borderPen, path);

            // Blue accent bar on left
            using var accentPath = CreateRoundedRect(new Rectangle(0, 0, 5, Height - 1), 12);
            using var accentBrush = new SolidBrush(Color.FromArgb(0, 120, 212));

            // Icon area - small "PC" circle
            using var circleBrush = new SolidBrush(Color.FromArgb(0, 120, 212));
            g.FillEllipse(circleBrush, 14, 14, 32, 32);
            using var iconFont = new Font("Segoe UI", 10, FontStyle.Bold);
            using var whiteBrush = new SolidBrush(Color.White);
            var iconSize = g.MeasureString("PC", iconFont);
            g.DrawString("PC", iconFont, whiteBrush,
                14 + (32 - iconSize.Width) / 2,
                14 + (32 - iconSize.Height) / 2);

            // Text
            using var titleFont = new Font("Segoe UI", 10f, FontStyle.Bold);
            using var subtitleFont = new Font("Segoe UI", 8.5f);
            using var textBrush = new SolidBrush(Color.FromArgb(220, 230, 245));
            using var subtitleBrush = new SolidBrush(Color.FromArgb(140, 160, 190));

            g.DrawString("For support, click the tray icon", titleFont, textBrush, 54, 12);
            g.DrawString("Right-click the PC icon near the clock  \u2192", subtitleFont, subtitleBrush, 54, 33);

            // Small X close button
            using var closeBrush = new SolidBrush(Color.FromArgb(100, 120, 150));
            using var closeFont = new Font("Segoe UI", 8f);
            g.DrawString("\u2715", closeFont, closeBrush, Width - 20, 4);
        }

        private static GraphicsPath CreateRoundedRect(Rectangle bounds, int radius)
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

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _fadeTimer?.Stop();
                _fadeTimer?.Dispose();
                _dismissTimer?.Stop();
                _dismissTimer?.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
