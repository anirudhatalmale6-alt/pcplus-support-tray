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
        private System.Windows.Forms.Timer? _fadeTimer;
        private float _opacity = 0f;
        private bool _fadingIn = true;
        private const int SHOW_DURATION_MS = 30000; // Show for 30 seconds then fade (non-persistent)
        private System.Windows.Forms.Timer? _dismissTimer;
        private readonly bool _persistent;

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

        public DesktopOverlay(bool persistent = false)
        {
            _persistent = persistent;

            FormBorderStyle = FormBorderStyle.None;
            ShowInTaskbar = false;
            TopMost = true;
            StartPosition = FormStartPosition.Manual;
            BackColor = Color.Magenta;
            TransparencyKey = Color.Magenta;
            Size = _persistent ? new Size(260, 44) : new Size(320, 60);
            DoubleBuffered = true;
            Opacity = 0;

            // Position near system tray (bottom-right, above taskbar)
            var workArea = Screen.PrimaryScreen!.WorkingArea;
            Location = new Point(workArea.Right - Width - 16, workArea.Bottom - Height - 8);

            if (!_persistent)
            {
                Click += (s, e) => FadeOut();
            }

            // Fade in
            _fadeTimer = new System.Windows.Forms.Timer { Interval = 30 };
            _fadeTimer.Tick += FadeStep;
            _fadeTimer.Start();

            if (!_persistent)
            {
                // Auto-dismiss after duration (only for non-persistent)
                _dismissTimer = new System.Windows.Forms.Timer { Interval = SHOW_DURATION_MS };
                _dismissTimer.Tick += (s, e) =>
                {
                    _dismissTimer?.Stop();
                    FadeOut();
                };
            }

            // Re-position on display settings change
            Microsoft.Win32.SystemEvents.DisplaySettingsChanged += (s, e) =>
            {
                var wa = Screen.PrimaryScreen!.WorkingArea;
                Location = new Point(wa.Right - Width - 16, wa.Bottom - Height - 8);
            };
        }

        private void FadeStep(object? sender, EventArgs e)
        {
            if (_fadingIn)
            {
                _opacity += 0.05f;
                float target = _persistent ? 0.75f : 0.92f;
                if (_opacity >= target)
                {
                    _opacity = target;
                    _fadingIn = false;
                    _fadeTimer?.Stop();
                    _dismissTimer?.Start(); // null-safe, only runs for non-persistent
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
            if (_persistent) return; // Persistent overlay cannot be dismissed
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
            using var path = CreateRoundedRect(rect, _persistent ? 8 : 12);
            using var bgBrush = new SolidBrush(Color.FromArgb(20, 30, 50));
            g.FillPath(bgBrush, path);

            // Blue accent border
            using var borderPen = new Pen(Color.FromArgb(0, 120, 212), _persistent ? 1.5f : 2f);
            g.DrawPath(borderPen, path);

            if (_persistent)
            {
                // Compact persistent widget
                // Small "PC" circle
                using var circleBrush = new SolidBrush(Color.FromArgb(0, 120, 212));
                g.FillEllipse(circleBrush, 8, 8, 28, 28);
                using var iconFont = new Font("Segoe UI", 8, FontStyle.Bold);
                using var whiteBrush = new SolidBrush(Color.White);
                var iconSize = g.MeasureString("PC", iconFont);
                g.DrawString("PC", iconFont, whiteBrush,
                    8 + (28 - iconSize.Width) / 2,
                    8 + (28 - iconSize.Height) / 2);

                // Text
                using var titleFont = new Font("Segoe UI", 8.5f, FontStyle.Bold);
                using var subtitleFont = new Font("Segoe UI", 7.5f);
                using var textBrush = new SolidBrush(Color.FromArgb(220, 230, 245));
                using var subtitleBrush = new SolidBrush(Color.FromArgb(140, 160, 190));

                g.DrawString("Need support?", titleFont, textBrush, 42, 6);
                g.DrawString("Right-click PC icon in tray \u2192", subtitleFont, subtitleBrush, 42, 23);
            }
            else
            {
                // Full-size first-run overlay
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
