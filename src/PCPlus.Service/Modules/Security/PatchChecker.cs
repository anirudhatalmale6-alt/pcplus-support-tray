using System.Runtime.InteropServices;
using System.Text.Json;
using PCPlus.Core.Interfaces;
using PCPlus.Core.Models;

namespace PCPlus.Service.Modules.Security
{
    public class PatchChecker : IDisposable
    {
        private IModuleContext _context = null!;
        private Timer? _checkTimer;
        private List<MissingPatch> _missingPatches = new();
        private DateTime _lastCheck = DateTime.MinValue;
        private readonly object _lock = new();

        private static readonly string CacheFile = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "PCPlusEndpoint", "missing-patches.json");

        public void Start(IModuleContext context)
        {
            _context = context;
            LoadCache();

            Task.Run(() => CheckForMissingPatches());

            _checkTimer = new Timer(_ => CheckForMissingPatches(), null,
                TimeSpan.FromHours(24), TimeSpan.FromHours(24));

            _context.Log(LogLevel.Info, "security", "Patch checker active");
        }

        public void Dispose()
        {
            _checkTimer?.Dispose();
        }

        public List<MissingPatch> GetMissingPatches()
        {
            lock (_lock) return new List<MissingPatch>(_missingPatches);
        }

        public DateTime GetLastCheckTime() => _lastCheck;

        private void CheckForMissingPatches()
        {
            try
            {
                var patches = new List<MissingPatch>();

                try
                {
                    var updateSession = Activator.CreateInstance(Type.GetTypeFromProgID("Microsoft.Update.Session")!);
                    if (updateSession == null) return;

                    var searcher = updateSession.GetType().InvokeMember("CreateUpdateSearcher",
                        System.Reflection.BindingFlags.InvokeMethod, null, updateSession, null);
                    if (searcher == null) return;

                    var result = searcher.GetType().InvokeMember("Search",
                        System.Reflection.BindingFlags.InvokeMethod, null, searcher,
                        new object[] { "IsInstalled=0 AND IsHidden=0" });
                    if (result == null) return;

                    var updates = result.GetType().InvokeMember("Updates",
                        System.Reflection.BindingFlags.GetProperty, null, result, null);
                    if (updates == null) return;

                    var count = (int)updates.GetType().InvokeMember("Count",
                        System.Reflection.BindingFlags.GetProperty, null, updates, null)!;

                    for (int i = 0; i < count && i < 100; i++)
                    {
                        try
                        {
                            var update = updates.GetType().InvokeMember("Item",
                                System.Reflection.BindingFlags.GetProperty, null, updates, new object[] { i });
                            if (update == null) continue;

                            var title = update.GetType().InvokeMember("Title",
                                System.Reflection.BindingFlags.GetProperty, null, update, null)?.ToString() ?? "";

                            var severity = "Unknown";
                            try
                            {
                                var msrcSeverity = update.GetType().InvokeMember("MsrcSeverity",
                                    System.Reflection.BindingFlags.GetProperty, null, update, null)?.ToString();
                                if (!string.IsNullOrEmpty(msrcSeverity))
                                    severity = msrcSeverity;
                            }
                            catch { }

                            var kbIds = new List<string>();
                            try
                            {
                                var kbCollection = update.GetType().InvokeMember("KBArticleIDs",
                                    System.Reflection.BindingFlags.GetProperty, null, update, null);
                                if (kbCollection != null)
                                {
                                    var kbCount = (int)kbCollection.GetType().InvokeMember("Count",
                                        System.Reflection.BindingFlags.GetProperty, null, kbCollection, null)!;
                                    for (int j = 0; j < kbCount; j++)
                                    {
                                        var kb = kbCollection.GetType().InvokeMember("Item",
                                            System.Reflection.BindingFlags.GetProperty, null, kbCollection, new object[] { j })?.ToString();
                                        if (!string.IsNullOrEmpty(kb))
                                            kbIds.Add($"KB{kb}");
                                    }
                                }
                            }
                            catch { }

                            patches.Add(new MissingPatch
                            {
                                Title = title,
                                Severity = severity,
                                KbArticles = kbIds,
                                DetectedAt = DateTime.UtcNow
                            });
                        }
                        catch { continue; }
                    }
                }
                catch (Exception ex)
                {
                    _context.Log(LogLevel.Warning, "security", $"WUA patch check failed: {ex.Message}");
                    CheckViaWmic(patches);
                }

                lock (_lock)
                {
                    _missingPatches = patches;
                    _lastCheck = DateTime.UtcNow;
                }

                SaveCache();

                _context.Log(LogLevel.Info, "security",
                    $"Patch check complete: {patches.Count} missing updates found");
            }
            catch (Exception ex)
            {
                _context.Log(LogLevel.Error, "security", $"Patch check error: {ex.Message}");
            }
        }

        private void CheckViaWmic(List<MissingPatch> patches)
        {
            try
            {
                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = "-NoProfile -NonInteractive -Command \"Get-HotFix | Select-Object -Property HotFixID,Description,InstalledOn | ConvertTo-Json\"",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using var proc = System.Diagnostics.Process.Start(psi);
                if (proc == null) return;
                var output = proc.StandardOutput.ReadToEnd();
                proc.WaitForExit(30000);
            }
            catch { }
        }

        private void LoadCache()
        {
            try
            {
                if (File.Exists(CacheFile))
                {
                    var json = File.ReadAllText(CacheFile);
                    var data = JsonSerializer.Deserialize<PatchCacheData>(json);
                    if (data != null)
                    {
                        lock (_lock)
                        {
                            _missingPatches = data.Patches ?? new();
                            _lastCheck = data.LastCheck;
                        }
                    }
                }
            }
            catch { }
        }

        private void SaveCache()
        {
            try
            {
                var data = new PatchCacheData
                {
                    Patches = _missingPatches,
                    LastCheck = _lastCheck
                };
                var json = JsonSerializer.Serialize(data, new JsonSerializerOptions { WriteIndented = true });
                Directory.CreateDirectory(Path.GetDirectoryName(CacheFile)!);
                File.WriteAllText(CacheFile, json);
            }
            catch { }
        }
    }

    public class MissingPatch
    {
        public string Title { get; set; } = "";
        public string Severity { get; set; } = "Unknown";
        public List<string> KbArticles { get; set; } = new();
        public DateTime DetectedAt { get; set; }
    }

    public class PatchCacheData
    {
        public List<MissingPatch> Patches { get; set; } = new();
        public DateTime LastCheck { get; set; }
    }
}
