using System.Net.Http.Json;
using System.Runtime.InteropServices;
using System.Text.Json;
using PCPlus.Core.Interfaces;
using PCPlus.Core.Models;

namespace PCPlus.Service.Modules.Telemetry
{
    public class TelemetryModule : IModule
    {
        public string Id => "telemetry";
        public string Name => "Telemetry";
        public string Version => "5.1.0";
        public LicenseTier RequiredTier => LicenseTier.Free;
        public bool IsRunning { get; private set; }

        private const string ModuleName = "telemetry";
        private static readonly string DataDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "PCPlusEndpoint");
        private static readonly string TelemetryPath = Path.Combine(DataDir, "telemetry.json");

        private IModuleContext _context = null!;
        private Timer? _dailyTimer;
        private Timer? _collectTimer;
        private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(30) };
        private TelemetryData _current = new();
        private DateTime _lastSent = DateTime.MinValue;
        private int _sendFailures;

        public Task InitializeAsync(IModuleContext context)
        {
            _context = context;
            LoadPersistedData();
            return Task.CompletedTask;
        }

        public Task StartAsync(CancellationToken cancellationToken)
        {
            IsRunning = true;

            _current.DeviceId = _context.Config.DeviceId;
            _current.CompanyName = _context.Config.CompanyName;
            _current.AppVersion = Version;
            _current.OsVersion = Environment.OSVersion.VersionString;
            _current.MachineName = Environment.MachineName;
            _current.ProcessorCount = Environment.ProcessorCount;
            _current.TotalMemoryMB = GetTotalMemoryMB();
            _current.LicenseTier = _context.Config.ActiveTier.ToString();
            _current.ServiceStartTime = DateTime.UtcNow;

            // Collect module stats every 5 minutes
            _collectTimer = new Timer(_ => CollectStats(), null,
                TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(5));

            // Send telemetry once per day (first send after 2 minutes to capture startup)
            _dailyTimer = new Timer(_ => SendTelemetry(), null,
                TimeSpan.FromMinutes(2), TimeSpan.FromHours(24));

            _context.Log(LogLevel.Info, ModuleName, "Telemetry active");
            return Task.CompletedTask;
        }

        public Task StopAsync()
        {
            _collectTimer?.Dispose();
            _dailyTimer?.Dispose();
            PersistData();
            IsRunning = false;
            return Task.CompletedTask;
        }

        public Task<ModuleResponse> HandleCommandAsync(ModuleCommand command)
        {
            return command.Action switch
            {
                "GetTelemetry" => Task.FromResult(ModuleResponse.Ok("", new Dictionary<string, object>
                {
                    ["data"] = _current,
                    ["lastSent"] = _lastSent
                })),
                "SendNow" => SendNowAsync(),
                _ => Task.FromResult(ModuleResponse.Fail($"Unknown: {command.Action}"))
            };
        }

        public ModuleStatus GetStatus() => new()
        {
            ModuleId = Id,
            ModuleName = Name,
            IsRunning = IsRunning,
            RequiredTier = RequiredTier,
            StatusText = IsRunning ? $"Active (last sent: {(_lastSent == DateTime.MinValue ? "never" : _lastSent.ToString("g"))})" : "Stopped",
            LastActivity = _lastSent,
            Metrics = new()
            {
                ["alertsRaised"] = _current.AlertsRaised,
                ["threatsBlocked"] = _current.ThreatsBlocked,
                ["sendFailures"] = _sendFailures
            }
        };

        private void CollectStats()
        {
            try
            {
                _current.UptimeMinutes = (int)(DateTime.UtcNow - _current.ServiceStartTime).TotalMinutes;
                _current.CollectedAt = DateTime.UtcNow;

                var moduleStats = new Dictionary<string, ModuleStatSnapshot>();
                foreach (var moduleId in new[] { "health", "security", "ransomware", "phishing", "maintenance", "policy", "customer-value" })
                {
                    var mod = _context.GetModule(moduleId);
                    if (mod == null) continue;

                    var status = mod.GetStatus();
                    moduleStats[moduleId] = new ModuleStatSnapshot
                    {
                        IsRunning = status.IsRunning,
                        StatusText = status.StatusText,
                        Metrics = status.Metrics
                    };
                }
                _current.ModuleStats = moduleStats;
            }
            catch (Exception ex)
            {
                _context.Log(LogLevel.Warning, ModuleName, $"Stats collection failed: {ex.Message}");
            }
        }

        private void SendTelemetry()
        {
            try
            {
                var apiUrl = _context.Config.DashboardApiUrl;
                if (string.IsNullOrEmpty(apiUrl))
                {
                    PersistData();
                    return;
                }

                CollectStats();

                var endpoint = apiUrl.TrimEnd('/') + "/api/telemetry";
                var token = _context.Config.DashboardApiToken;

                var request = new HttpRequestMessage(HttpMethod.Post, endpoint);
                if (!string.IsNullOrEmpty(token))
                    request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);

                request.Content = JsonContent.Create(_current);

                var response = _http.Send(request);
                if (response.IsSuccessStatusCode)
                {
                    _lastSent = DateTime.UtcNow;
                    _sendFailures = 0;
                    _current.AlertsRaised = 0;
                    _current.ThreatsBlocked = 0;
                    _current.HardeningFailures.Clear();
                    _current.ErrorLog.Clear();
                    _context.Log(LogLevel.Info, ModuleName, "Telemetry sent successfully");
                }
                else
                {
                    _sendFailures++;
                    _context.Log(LogLevel.Warning, ModuleName,
                        $"Telemetry send failed: HTTP {(int)response.StatusCode}");
                }

                PersistData();
            }
            catch (Exception ex)
            {
                _sendFailures++;
                _context.Log(LogLevel.Warning, ModuleName, $"Telemetry send error: {ex.Message}");
                PersistData();
            }
        }

        private Task<ModuleResponse> SendNowAsync()
        {
            SendTelemetry();
            return Task.FromResult(ModuleResponse.Ok($"Telemetry sent (failures: {_sendFailures})"));
        }

        public void RecordAlert(string moduleId, string title, string severity)
        {
            _current.AlertsRaised++;
            if (_current.RecentAlerts.Count >= 50)
                _current.RecentAlerts.RemoveAt(0);
            _current.RecentAlerts.Add(new AlertSummary
            {
                ModuleId = moduleId,
                Title = title,
                Severity = severity,
                Timestamp = DateTime.UtcNow
            });
        }

        public void RecordThreatBlocked(string type)
        {
            _current.ThreatsBlocked++;
            _current.ThreatTypes.TryGetValue(type, out var count);
            _current.ThreatTypes[type] = count + 1;
        }

        public void RecordHardeningResult(string rule, bool success, string detail = "")
        {
            if (!success)
            {
                _current.HardeningFailures[rule] = detail;
            }
            _current.HardeningResults[rule] = success;
        }

        public void RecordError(string module, string error)
        {
            if (_current.ErrorLog.Count >= 100)
                _current.ErrorLog.RemoveAt(0);
            _current.ErrorLog.Add($"[{DateTime.UtcNow:HH:mm}] {module}: {error}");
        }

        private void PersistData()
        {
            try
            {
                Directory.CreateDirectory(DataDir);
                var json = JsonSerializer.Serialize(_current);
                var tempPath = TelemetryPath + ".tmp";
                File.WriteAllText(tempPath, json);
                File.Move(tempPath, TelemetryPath, overwrite: true);
            }
            catch { }
        }

        private void LoadPersistedData()
        {
            try
            {
                if (!File.Exists(TelemetryPath)) return;
                var json = File.ReadAllText(TelemetryPath);
                var data = JsonSerializer.Deserialize<TelemetryData>(json);
                if (data != null)
                    _current = data;
            }
            catch { }
        }

        private static long GetTotalMemoryMB()
        {
            try
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    GetPhysicallyInstalledSystemMemory(out long kb);
                    return kb / 1024;
                }
            }
            catch { }
            return 0;
        }

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetPhysicallyInstalledSystemMemory(out long totalKB);
    }

    public class TelemetryData
    {
        public string DeviceId { get; set; } = "";
        public string CompanyName { get; set; } = "";
        public string MachineName { get; set; } = "";
        public string AppVersion { get; set; } = "";
        public string OsVersion { get; set; } = "";
        public string LicenseTier { get; set; } = "";
        public int ProcessorCount { get; set; }
        public long TotalMemoryMB { get; set; }
        public DateTime ServiceStartTime { get; set; }
        public DateTime CollectedAt { get; set; }
        public int UptimeMinutes { get; set; }

        // Counters (reset after each successful send)
        public int AlertsRaised { get; set; }
        public int ThreatsBlocked { get; set; }
        public Dictionary<string, int> ThreatTypes { get; set; } = new();
        public List<AlertSummary> RecentAlerts { get; set; } = new();

        // Hardening results
        public Dictionary<string, bool> HardeningResults { get; set; } = new();
        public Dictionary<string, string> HardeningFailures { get; set; } = new();

        // Module snapshots
        public Dictionary<string, ModuleStatSnapshot> ModuleStats { get; set; } = new();

        // Error log (capped at 100 entries)
        public List<string> ErrorLog { get; set; } = new();
    }

    public class AlertSummary
    {
        public string ModuleId { get; set; } = "";
        public string Title { get; set; } = "";
        public string Severity { get; set; } = "";
        public DateTime Timestamp { get; set; }
    }

    public class ModuleStatSnapshot
    {
        public bool IsRunning { get; set; }
        public string StatusText { get; set; } = "";
        public Dictionary<string, object> Metrics { get; set; } = new();
    }
}
