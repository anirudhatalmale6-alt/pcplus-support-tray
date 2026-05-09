using System.Diagnostics;
using System.IO.Compression;
using System.Net.Http.Json;
using System.Text.Json;
using PCPlus.Core.Interfaces;

namespace PCPlus.Service.Engine
{
    /// <summary>
    /// Automatic update checker and installer.
    /// Checks GitHub releases for new versions, downloads and installs silently.
    /// Restarts the service after update.
    /// </summary>
    public class AutoUpdater : IDisposable
    {
        private readonly ServiceConfig _config;
        private readonly ModuleEngine _engine;
        private Timer? _checkTimer;
        private bool _updateInProgress;
        private bool _disposed;

        private const string GITHUB_REPO = "anirudhatalmale6-alt/pcplus-support-tray";
        private const string UPDATE_CHECK_INTERVAL_HOURS = "6";

        public string CurrentVersion { get; }
        public string? LatestVersion { get; private set; }
        public bool UpdateAvailable { get; private set; }
        public DateTime LastChecked { get; private set; }
        public string UpdateStatus { get; private set; } = "idle";

        public AutoUpdater(ServiceConfig config, ModuleEngine engine)
        {
            _config = config;
            _engine = engine;
            CurrentVersion = typeof(AutoUpdater).Assembly.GetName().Version?.ToString(3) ?? "4.0.0";
        }

        public void Start()
        {
            // Check for updates on startup (after 2 minutes) then every 6 hours
            var interval = TimeSpan.FromHours(double.Parse(
                _config.GetValue("autoUpdateIntervalHours") ?? UPDATE_CHECK_INTERVAL_HOURS));

            _checkTimer = new Timer(async _ => await CheckForUpdateAsync(),
                null, TimeSpan.FromMinutes(2), interval);

            _engine.Log(LogLevel.Info, "auto-updater",
                $"Auto-updater started (current: v{CurrentVersion}, check interval: {interval.TotalHours}h)");
        }

        public async Task CheckForUpdateAsync()
        {
            if (_updateInProgress) return;

            try
            {
                UpdateStatus = "checking";
                LastChecked = DateTime.UtcNow;

                using var http = new HttpClient();
                http.DefaultRequestHeaders.Add("User-Agent", "PCPlus-Endpoint-Protection");
                http.Timeout = TimeSpan.FromSeconds(15);

                // Check GitHub releases API
                var response = await http.GetAsync(
                    $"https://api.github.com/repos/{GITHUB_REPO}/releases/latest");

                if (!response.IsSuccessStatusCode)
                {
                    UpdateStatus = "check_failed";
                    _engine.Log(LogLevel.Warning, "auto-updater",
                        $"Update check failed: {response.StatusCode}");
                    return;
                }

                var release = await response.Content.ReadFromJsonAsync<JsonElement>();
                var tagName = release.GetProperty("tag_name").GetString() ?? "";
                var latestVer = tagName.TrimStart('v');
                LatestVersion = latestVer;

                if (IsNewerVersion(latestVer, CurrentVersion))
                {
                    UpdateAvailable = true;
                    UpdateStatus = "update_available";
                    _engine.Log(LogLevel.Info, "auto-updater",
                        $"Update available: v{CurrentVersion} -> v{latestVer}");

                    // Check if auto-install is enabled
                    var autoInstall = _config.GetValue("autoUpdateInstall")?.ToLower() == "true";
                    if (autoInstall)
                    {
                        await DownloadAndInstallAsync(release);
                    }
                    else
                    {
                        // Report update available to dashboard
                        _engine.Log(LogLevel.Info, "auto-updater",
                            $"Auto-install disabled. Update v{latestVer} available for manual install.");
                    }
                }
                else
                {
                    UpdateAvailable = false;
                    UpdateStatus = "up_to_date";
                }
            }
            catch (Exception ex)
            {
                UpdateStatus = "check_failed";
                _engine.Log(LogLevel.Warning, "auto-updater", $"Update check error: {ex.Message}");
            }
        }

        private async Task DownloadAndInstallAsync(JsonElement release)
        {
            _updateInProgress = true;
            UpdateStatus = "downloading";

            try
            {
                var tagName = release.GetProperty("tag_name").GetString() ?? "";
                var assets = release.GetProperty("assets");

                // Find the ZIP asset (PCPlus-EndpointProtection-*.zip)
                string? downloadUrl = null;
                foreach (var asset in assets.EnumerateArray())
                {
                    var name = asset.GetProperty("name").GetString() ?? "";
                    if (name.EndsWith(".zip", StringComparison.OrdinalIgnoreCase) &&
                        name.Contains("PCPlus", StringComparison.OrdinalIgnoreCase))
                    {
                        downloadUrl = asset.GetProperty("browser_download_url").GetString();
                        break;
                    }
                }

                if (downloadUrl == null)
                {
                    UpdateStatus = "no_asset";
                    _engine.Log(LogLevel.Warning, "auto-updater", "No downloadable asset found in release");
                    return;
                }

                // Download to temp
                var tempDir = Path.Combine(Path.GetTempPath(), "pcplus-update");
                Directory.CreateDirectory(tempDir);
                var zipPath = Path.Combine(tempDir, $"update-{tagName}.zip");

                using var http = new HttpClient();
                http.DefaultRequestHeaders.Add("User-Agent", "PCPlus-Endpoint-Protection");
                http.Timeout = TimeSpan.FromMinutes(5);

                _engine.Log(LogLevel.Info, "auto-updater", $"Downloading update {tagName}...");
                var data = await http.GetByteArrayAsync(downloadUrl);
                await File.WriteAllBytesAsync(zipPath, data);

                _engine.Log(LogLevel.Info, "auto-updater",
                    $"Downloaded {data.Length / 1024 / 1024}MB. Installing...");

                UpdateStatus = "installing";

                // Extract to staging directory
                var stagingDir = Path.Combine(tempDir, "staging");
                if (Directory.Exists(stagingDir)) Directory.Delete(stagingDir, true);
                ZipFile.ExtractToDirectory(zipPath, stagingDir);

                // Create update script that will:
                // 1. Stop the service
                // 2. Copy new files over old ones
                // 3. Start the service
                // Detect actual install path from the running executable's location
                var installDir = Path.GetDirectoryName(Environment.ProcessPath)
                    ?? Path.GetDirectoryName(typeof(AutoUpdater).Assembly.Location)
                    ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "PCPlus");
                var scriptPath = Path.Combine(tempDir, "apply-update.ps1");

                var updateScript = $@"
# PC Plus Auto-Update Script
Start-Sleep -Seconds 3
$ErrorActionPreference = 'Stop'

try {{
    # Kill tray app if running
    Get-Process -Name 'PCPlusSupportTray' -ErrorAction SilentlyContinue | Stop-Process -Force
    Start-Sleep -Seconds 1

    # Stop service
    Stop-Service -Name 'PCPlusEndpoint' -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2

    # Backup current version
    $backupDir = '{installDir}\backup-{CurrentVersion}'
    if (-not (Test-Path $backupDir)) {{ New-Item -Path $backupDir -ItemType Directory -Force | Out-Null }}
    Copy-Item -Path '{installDir}\*.exe' -Destination $backupDir -Force -ErrorAction SilentlyContinue
    Copy-Item -Path '{installDir}\*.dll' -Destination $backupDir -Force -ErrorAction SilentlyContinue

    # Copy new files
    $sourceDir = '{stagingDir}'
    $sourceFiles = Get-ChildItem -Path $sourceDir -Recurse -File
    foreach ($file in $sourceFiles) {{
        $relativePath = $file.FullName.Substring($sourceDir.Length + 1)
        $destPath = Join-Path '{installDir}' $relativePath
        $destDir = Split-Path $destPath -Parent
        if (-not (Test-Path $destDir)) {{ New-Item -Path $destDir -ItemType Directory -Force | Out-Null }}
        Copy-Item -Path $file.FullName -Destination $destPath -Force
    }}

    # Verify key files exist after copy
    if (-not (Test-Path '{installDir}\PCPlusSupportTray.exe') -and -not (Test-Path '{installDir}\PCPlusService.exe')) {{
        throw 'Update files not found after copy - rolling back'
    }}

    # Start service
    Start-Service -Name 'PCPlusEndpoint' -ErrorAction SilentlyContinue

    # Restart tray app for logged-in user
    $trayExe = '{installDir}\PCPlusSupportTray.exe'
    if (Test-Path $trayExe) {{
        Start-Process -FilePath $trayExe -ErrorAction SilentlyContinue
    }}

    # Log success
    $logDir = '{Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "PCPlusEndpoint", "Logs")}'
    if (-not (Test-Path $logDir)) {{ New-Item -Path $logDir -ItemType Directory -Force | Out-Null }}
    Add-Content -Path ""$logDir\updates.log"" -Value ""[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Updated from v{CurrentVersion} to {tagName} - SUCCESS""
}} catch {{
    # Rollback from backup
    $backupDir = '{installDir}\backup-{CurrentVersion}'
    if (Test-Path $backupDir) {{
        Copy-Item -Path ""$backupDir\*"" -Destination '{installDir}' -Force -ErrorAction SilentlyContinue
    }}
    Start-Service -Name 'PCPlusEndpoint' -ErrorAction SilentlyContinue
    $trayExe = '{installDir}\PCPlusSupportTray.exe'
    if (Test-Path $trayExe) {{ Start-Process -FilePath $trayExe -ErrorAction SilentlyContinue }}

    $logDir = '{Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "PCPlusEndpoint", "Logs")}'
    if (-not (Test-Path $logDir)) {{ New-Item -Path $logDir -ItemType Directory -Force | Out-Null }}
    Add-Content -Path ""$logDir\updates.log"" -Value ""[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Update to {tagName} FAILED - rolled back: $_""
}} finally {{
    # Cleanup
    Remove-Item -Path '{zipPath}' -Force -ErrorAction SilentlyContinue
    Remove-Item -Path '{stagingDir}' -Recurse -Force -ErrorAction SilentlyContinue
}}
";

                await File.WriteAllTextAsync(scriptPath, updateScript);

                // Launch update script detached (will stop this service, copy files, restart)
                var psi = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-ExecutionPolicy Bypass -WindowStyle Hidden -File \"{scriptPath}\"",
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                Process.Start(psi);

                UpdateStatus = "update_applied";
                _engine.Log(LogLevel.Info, "auto-updater",
                    $"Update script launched. Service will restart with v{tagName}.");
            }
            catch (Exception ex)
            {
                UpdateStatus = "install_failed";
                _engine.Log(LogLevel.Error, "auto-updater", $"Update install failed: {ex.Message}");
            }
            finally
            {
                _updateInProgress = false;
            }
        }

        private static bool IsNewerVersion(string latest, string current)
        {
            try
            {
                var latestParts = latest.Split('.').Select(int.Parse).ToArray();
                var currentParts = current.Split('.').Select(int.Parse).ToArray();

                for (int i = 0; i < Math.Min(latestParts.Length, currentParts.Length); i++)
                {
                    if (latestParts[i] > currentParts[i]) return true;
                    if (latestParts[i] < currentParts[i]) return false;
                }
                return latestParts.Length > currentParts.Length;
            }
            catch { return false; }
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            _checkTimer?.Dispose();
        }
    }
}
