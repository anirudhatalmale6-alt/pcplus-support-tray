using System;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Windows.Forms;

namespace SupportTray
{
    public static class ScreenCapture
    {
        private static readonly string ScreenshotDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "PCPlusSupport", "Screenshots");

        public static string CaptureFullScreen()
        {
            Directory.CreateDirectory(ScreenshotDir);

            var bounds = Screen.PrimaryScreen!.Bounds;
            using var bitmap = new Bitmap(bounds.Width, bounds.Height);
            using var graphics = Graphics.FromImage(bitmap);
            graphics.CopyFromScreen(bounds.Location, Point.Empty, bounds.Size);

            var timestamp = DateTime.Now.ToString("yyyy-MM-dd_HH-mm-ss");
            var filename = $"screenshot_{timestamp}.png";
            var filepath = Path.Combine(ScreenshotDir, filename);

            bitmap.Save(filepath, ImageFormat.Png);
            return filepath;
        }

        public static string CaptureAllScreens()
        {
            Directory.CreateDirectory(ScreenshotDir);

            var allBounds = Rectangle.Empty;
            foreach (var screen in Screen.AllScreens)
            {
                allBounds = Rectangle.Union(allBounds, screen.Bounds);
            }

            using var bitmap = new Bitmap(allBounds.Width, allBounds.Height);
            using var graphics = Graphics.FromImage(bitmap);
            graphics.CopyFromScreen(allBounds.Location, Point.Empty, allBounds.Size);

            var timestamp = DateTime.Now.ToString("yyyy-MM-dd_HH-mm-ss");
            var filename = $"screenshot_all_{timestamp}.png";
            var filepath = Path.Combine(ScreenshotDir, filename);

            bitmap.Save(filepath, ImageFormat.Png);
            return filepath;
        }

        public static void OpenScreenshotFolder()
        {
            Directory.CreateDirectory(ScreenshotDir);
            System.Diagnostics.Process.Start("explorer.exe", ScreenshotDir);
        }
    }
}
