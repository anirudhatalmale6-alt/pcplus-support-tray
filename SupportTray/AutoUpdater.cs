using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace SupportTray
{
    public class AutoUpdater
    {
        private const string GITHUB_REPO = "anirudhatalmale6-alt/pcplus-support-tray";
        private const string GITHUB_API = "https://api.github.com/repos/" + GITHUB_REPO + "/releases/latest";
        private static readonly string UpdateDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "PCPlusSupport", "Updates");

        private readonly string _currentVersion;
        private readonly NotifyIcon? _trayIcon;

        public AutoUpdater(string currentVersion, NotifyIcon? trayIcon = null)
        {
            _currentVersion = currentVersion;
            _trayIcon = trayIcon;
        }

        public async Task CheckAndUpdateAsync(bool silent = true)
        {
            try
            {
                using var http = new HttpClient();
                http.DefaultRequestHeaders.Add("User-Agent", "PCPlusSupportTray");
                http.Timeout = TimeSpan.FromSeconds(15);

                var json = await http.GetStringAsync(GITHUB_API);
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;

                var tagName = root.GetProperty("tag_name").GetString() ?? "";
                var remoteVersion = tagName.TrimStart('v', 'V');

                if (!IsNewerVersion(remoteVersion, _currentVersion))
                {
                    if (!silent)
                        MessageBox.Show($"You are running the latest version (v{_currentVersion}).",
                            "No Update Available", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }

                // Find the zip asset
                string? downloadUrl = null;
                string? assetName = null;
                foreach (var asset in root.GetProperty("assets").EnumerateArray())
                {
                    var name = asset.GetProperty("name").GetString() ?? "";
                    if (name.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
                    {
                        downloadUrl = asset.GetProperty("browser_download_url").GetString();
                        assetName = name;
                        break;
                    }
                }

                if (downloadUrl == null)
                {
                    if (!silent)
                        MessageBox.Show("Update found but no download available.", "Update Error",
                            MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                // Notify user
                var result = MessageBox.Show(
                    $"A new version (v{remoteVersion}) is available!\n" +
                    $"You are currently running v{_currentVersion}.\n\n" +
                    $"Would you like to update now?",
                    "Update Available",
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Information);

                if (result != DialogResult.Yes) return;

                // Show progress via balloon
                if (_trayIcon != null)
                {
                    _trayIcon.BalloonTipTitle = "Updating...";
                    _trayIcon.BalloonTipText = $"Downloading v{remoteVersion}...";
                    _trayIcon.BalloonTipIcon = ToolTipIcon.Info;
                    _trayIcon.ShowBalloonTip(3000);
                }

                // Download
                Directory.CreateDirectory(UpdateDir);
                var zipPath = Path.Combine(UpdateDir, assetName!);
                var extractDir = Path.Combine(UpdateDir, "extracted");

                using (var response = await http.GetAsync(downloadUrl))
                {
                    response.EnsureSuccessStatusCode();
                    var bytes = await response.Content.ReadAsByteArrayAsync();
                    await File.WriteAllBytesAsync(zipPath, bytes);
                }

                // Extract
                if (Directory.Exists(extractDir))
                    Directory.Delete(extractDir, true);
                ZipFile.ExtractToDirectory(zipPath, extractDir);

                // Create update batch script that:
                // 1. Waits for current process to exit
                // 2. Copies new files to install dir
                // 3. Restarts the app
                var installDir = AppDomain.CurrentDomain.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar);
                var batchPath = Path.Combine(UpdateDir, "apply_update.bat");
                var batchContent =
                    "@echo off\r\n" +
                    "echo Applying PC Plus Support update...\r\n" +
                    $"timeout /t 3 /nobreak >nul\r\n" +
                    $"copy /Y \"{extractDir}\\PCPlusSupportTray.exe\" \"{installDir}\\\" >nul 2>&1\r\n" +
                    $"if exist \"{extractDir}\\icon.ico\" copy /Y \"{extractDir}\\icon.ico\" \"{installDir}\\\" >nul 2>&1\r\n" +
                    $"start \"\" \"{installDir}\\PCPlusSupportTray.exe\"\r\n" +
                    $"rd /s /q \"{UpdateDir}\" >nul 2>&1\r\n" +
                    "exit\r\n";

                await File.WriteAllTextAsync(batchPath, batchContent);

                // Launch the update script and exit
                Process.Start(new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = $"/c \"{batchPath}\"",
                    WindowStyle = ProcessWindowStyle.Hidden,
                    CreateNoWindow = true
                });

                // Exit the app so files can be replaced
                if (_trayIcon != null)
                    _trayIcon.Visible = false;
                Application.Exit();
            }
            catch (Exception ex)
            {
                if (!silent)
                    MessageBox.Show($"Update check failed:\n{ex.Message}", "Update Error",
                        MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        private static bool IsNewerVersion(string remote, string current)
        {
            try
            {
                var remoteVer = Version.Parse(NormalizeVersion(remote));
                var currentVer = Version.Parse(NormalizeVersion(current));
                return remoteVer > currentVer;
            }
            catch
            {
                return false;
            }
        }

        private static string NormalizeVersion(string v)
        {
            v = v.TrimStart('v', 'V');
            var parts = v.Split('.');
            // Ensure at least major.minor.patch
            while (parts.Length < 3)
            {
                v += ".0";
                parts = v.Split('.');
            }
            return v;
        }
    }
}
