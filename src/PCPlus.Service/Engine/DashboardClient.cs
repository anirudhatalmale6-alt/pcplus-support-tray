using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Text.Json;
using PCPlus.Core.Interfaces;
using PCPlus.Core.Models;

namespace PCPlus.Service.Engine
{
    /// <summary>
    /// Phone-home client that reports endpoint status to the central dashboard.
    /// Sends heartbeats every 30 seconds, reports alerts in real-time,
    /// and picks up config changes pushed from the dashboard.
    /// </summary>
    public class DashboardClient : IDisposable
    {
        private readonly ServiceConfig _config;
        private readonly ModuleEngine _engine;
        private HttpClient? _http;
        private Timer? _heartbeatTimer;
        private bool _disposed;
        private int _heartbeatCount;

        public bool IsConnected { get; private set; }
        public DateTime LastHeartbeat { get; private set; }

        public DashboardClient(ServiceConfig config, ModuleEngine engine)
        {
            _config = config;
            _engine = engine;
        }

        public void Start()
        {
            var dashboardUrl = _config.DashboardApiUrl;
            if (string.IsNullOrEmpty(dashboardUrl))
            {
                _engine.Log(LogLevel.Info, "dashboard-client", "Dashboard URL not configured - phone-home disabled");
                return;
            }

            _http = new HttpClient
            {
                BaseAddress = new Uri(dashboardUrl.TrimEnd('/')),
                Timeout = TimeSpan.FromSeconds(10)
            };

            var token = _config.DashboardApiToken;
            if (!string.IsNullOrEmpty(token))
                _http.DefaultRequestHeaders.Add("X-Api-Token", token);

            // Subscribe to alerts to forward them to dashboard
            _engine.OnAlert += ForwardAlert;

            // Start heartbeat timer (every 30 seconds)
            _heartbeatTimer = new Timer(SendHeartbeat, null, TimeSpan.Zero, TimeSpan.FromSeconds(30));

            _engine.Log(LogLevel.Info, "dashboard-client", $"Phone-home started -> {dashboardUrl}");
        }

        public void Stop()
        {
            _heartbeatTimer?.Dispose();
            _engine.OnAlert -= ForwardAlert;
        }

        private async void SendHeartbeat(object? state)
        {
            if (_http == null) return;

            try
            {
                // Get current health from health module
                var healthModule = _engine.GetModule("health");
                float cpu = 0, ram = 0, disk = 0, cpuTemp = 0, gpuTemp = 0;
                if (healthModule?.IsRunning == true)
                {
                    var result = await healthModule.HandleCommandAsync(new ModuleCommand
                    {
                        ModuleId = "health",
                        Action = "GetHealthSnapshot"
                    });
                    if (result.Success && result.Data.TryGetValue("snapshot", out var snapObj))
                    {
                        // Parse snapshot from module response
                        var json = JsonSerializer.Serialize(snapObj);
                        var snap = JsonSerializer.Deserialize<HealthSnapshot>(json);
                        if (snap != null)
                        {
                            cpu = snap.CpuPercent;
                            ram = snap.RamPercent;
                            disk = snap.Disks.FirstOrDefault()?.UsedPercent ?? 0;
                            cpuTemp = snap.CpuTempC;
                            gpuTemp = snap.GpuTempC;
                        }
                    }
                }

                // Get security score and check details from module
                var secModule = _engine.GetModule("security");
                int secScore = 0;
                string secGrade = "?";
                var securityChecks = new List<object>();
                if (secModule?.IsRunning == true)
                {
                    var status = secModule.GetStatus();
                    if (status.Metrics.TryGetValue("score", out var scoreObj))
                        secScore = Convert.ToInt32(scoreObj);
                    if (status.Metrics.TryGetValue("grade", out var gradeObj))
                        secGrade = gradeObj?.ToString() ?? "?";

                    // Get detailed check results
                    try
                    {
                        var secResult = await secModule.HandleCommandAsync(new ModuleCommand
                        {
                            ModuleId = "security",
                            Action = "GetSecurityReport"
                        });
                        if (secResult.Success && secResult.Data.TryGetValue("result", out var resultObj))
                        {
                            var json = JsonSerializer.Serialize(resultObj);
                            var scanResult = JsonSerializer.Deserialize<SecurityScanResult>(json,
                                new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                            if (scanResult?.Checks != null)
                            {
                                securityChecks = scanResult.Checks.Select(c => (object)new
                                {
                                    id = c.Id,
                                    name = c.Name,
                                    category = c.Category,
                                    passed = c.Passed,
                                    detail = c.Detail,
                                    recommendation = c.Recommendation,
                                    weight = c.Weight
                                }).ToList();
                            }
                        }
                    }
                    catch { }
                }

                // Count running modules
                var runningCount = _engine.GetAllModules().Count(m => m.IsRunning);

                // Get local IP
                var localIp = GetLocalIpAddress();

                // Get public IP (cached, refreshed every 5 minutes)
                var publicIp = await GetPublicIpAddress();

                // Collect software inventory every 10th heartbeat (~5 minutes)
                _heartbeatCount++;
                var installedSoftware = new List<object>();
                if (_heartbeatCount % 10 == 1)
                {
                    try
                    {
                        installedSoftware = CollectSoftwareInventory();
                    }
                    catch { }
                }

                var heartbeat = new
                {
                    deviceId = _config.DeviceId,
                    hostname = Environment.MachineName,
                    osVersion = GetFriendlyOsVersion(),
                    agentVersion = typeof(DashboardClient).Assembly.GetName().Version?.ToString(3) ?? "4.3.0",
                    licenseTier = _engine.License.Tier.ToString(),
                    customerName = _config.CompanyName,
                    localIp = localIp,
                    publicIp = publicIp,
                    cpuPercent = cpu,
                    ramPercent = ram,
                    diskPercent = disk,
                    cpuTempC = cpuTemp,
                    gpuTempC = gpuTemp,
                    securityScore = secScore,
                    securityGrade = secGrade,
                    lockdownActive = false,
                    activeAlerts = 0,
                    runningModules = runningCount,
                    modules = new List<object>(),
                    securityChecks = securityChecks,
                    installedSoftware = installedSoftware.Count > 0 ? installedSoftware : null
                };

                var response = await _http.PostAsJsonAsync("/api/endpoint/heartbeat", heartbeat);

                if (response.IsSuccessStatusCode)
                {
                    IsConnected = true;
                    LastHeartbeat = DateTime.UtcNow;

                    // Process any pending config changes from dashboard
                    var result = await response.Content.ReadFromJsonAsync<HeartbeatResponse>();
                    if (result?.PendingConfig?.Count > 0)
                    {
                        await ApplyConfigChanges(result.PendingConfig);
                    }
                    if (!string.IsNullOrEmpty(result?.Command))
                    {
                        await ExecuteCommand(result.Command);
                    }
                    // Sync customer name from dashboard (dashboard is source of truth)
                    if (!string.IsNullOrEmpty(result?.CustomerName) && !result.CustomerName.Contains("{{")
                        && result.CustomerName != _config.CompanyName)
                    {
                        _config.SetValue("companyName", result.CustomerName);
                        _engine.Log(LogLevel.Info, "dashboard-client",
                            $"Customer name synced from dashboard: {result.CustomerName}");
                    }
                }
                else
                {
                    IsConnected = false;
                    var body = await response.Content.ReadAsStringAsync();
                    _engine.Log(LogLevel.Warning, "dashboard-client",
                        $"Heartbeat rejected: {response.StatusCode} - {body}");
                }
            }
            catch (Exception ex)
            {
                IsConnected = false;
                _engine.Log(LogLevel.Warning, "dashboard-client", $"Heartbeat failed: {ex.Message}");
            }
        }

        private async void ForwardAlert(Alert alert)
        {
            if (_http == null) return;

            try
            {
                var report = new
                {
                    deviceId = _config.DeviceId,
                    hostname = Environment.MachineName,
                    moduleId = alert.ModuleId,
                    title = alert.Title,
                    message = alert.Message,
                    severity = alert.Severity.ToString(),
                    category = alert.Category,
                    metadata = alert.Metadata
                };

                await _http.PostAsJsonAsync("/api/endpoint/alert", report);
            }
            catch { }
        }

        private async Task ApplyConfigChanges(List<ConfigChange> changes)
        {
            var appliedIds = new List<int>();

            foreach (var change in changes)
            {
                if (change.Key == "_command")
                {
                    await ExecuteCommand(change.Value);
                }
                else if (change.Key == "_remediate")
                {
                    // Execute security remediation for a specific check
                    var secModule = _engine.GetModule("security");
                    if (secModule?.IsRunning == true)
                    {
                        var remResult = await secModule.HandleCommandAsync(new ModuleCommand
                        {
                            ModuleId = "security",
                            Action = "Remediate",
                            Parameters = new() { ["checkId"] = change.Value }
                        });
                        _engine.Log(remResult.Success ? LogLevel.Info : LogLevel.Warning, "dashboard-client",
                            $"Remediation '{change.Value}': {(remResult.Success ? "OK" : "FAILED")} - {remResult.Message}");
                    }
                }
                else
                {
                    _config.SetValue(change.Key, change.Value);
                    _engine.Log(LogLevel.Info, "dashboard-client",
                        $"Config updated from dashboard: {change.Key} = {change.Value}");
                }
                appliedIds.Add(change.Id);
            }

            if (appliedIds.Count > 0)
            {
                _config.Save();

                // Notify modules of config change
                await _engine.BroadcastEventAsync(new ModuleEvent
                {
                    SourceModule = "dashboard-client",
                    EventType = ModuleEvent.CONFIG_CHANGED
                });

                // Acknowledge applied configs
                try
                {
                    await _http!.PostAsJsonAsync("/api/endpoint/heartbeat/ack", appliedIds);
                }
                catch { }
            }
        }

        private async Task ExecuteCommand(string command)
        {
            _engine.Log(LogLevel.Info, "dashboard-client", $"Executing dashboard command: {command}");

            switch (command.ToLower())
            {
                case "rescan":
                    var secModule = _engine.GetModule("security");
                    if (secModule?.IsRunning == true)
                        await secModule.HandleCommandAsync(new ModuleCommand { ModuleId = "security", Action = "RunSecurityScan" });
                    break;

                case "maintenance":
                    var mntModule = _engine.GetModule("maintenance");
                    if (mntModule?.IsRunning == true)
                        await mntModule.HandleCommandAsync(new ModuleCommand
                        {
                            ModuleId = "maintenance",
                            Action = "RunMaintenance",
                            Parameters = new() { ["action"] = "fixmypc" }
                        });
                    break;

                case "lockdown":
                    var rwModule = _engine.GetModule("ransomware");
                    if (rwModule?.IsRunning == true)
                        await rwModule.HandleCommandAsync(new ModuleCommand { ModuleId = "ransomware", Action = "ActivateLockdown" });
                    break;
            }
        }

        private static string GetFriendlyOsVersion()
        {
            try
            {
                var ver = Environment.OSVersion.Version;
                var build = ver.Build;
                string name;
                if (ver.Major == 10 && build >= 22000)
                    name = "Windows 11";
                else if (ver.Major == 10)
                    name = "Windows 10";
                else if (ver.Major == 6 && ver.Minor == 3)
                    name = "Windows 8.1";
                else if (ver.Major == 6 && ver.Minor == 2)
                    name = "Windows 8";
                else if (ver.Major == 6 && ver.Minor == 1)
                    name = "Windows 7";
                else
                    name = $"Windows {ver.Major}.{ver.Minor}";

                return $"{name} (Build {build})";
            }
            catch
            {
                return Environment.OSVersion.VersionString;
            }
        }

        private static string GetLocalIpAddress()
        {
            try
            {
                using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, 0);
                socket.Connect("8.8.8.8", 65530);
                if (socket.LocalEndPoint is IPEndPoint endPoint)
                    return endPoint.Address.ToString();
            }
            catch { }
            return "0.0.0.0";
        }

        private string? _cachedPublicIp;
        private DateTime _publicIpLastFetched = DateTime.MinValue;

        private async Task<string> GetPublicIpAddress()
        {
            // Cache public IP for 5 minutes
            if (_cachedPublicIp != null && (DateTime.UtcNow - _publicIpLastFetched).TotalMinutes < 5)
                return _cachedPublicIp;

            try
            {
                using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
                _cachedPublicIp = (await client.GetStringAsync("https://api.ipify.org")).Trim();
                _publicIpLastFetched = DateTime.UtcNow;
            }
            catch
            {
                _cachedPublicIp ??= "";
            }
            return _cachedPublicIp;
        }

        private List<object> CollectSoftwareInventory()
        {
            var software = new List<object>();
            foreach (var regPath in new[] {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
            })
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(regPath);
                if (key == null) continue;
                foreach (var subKeyName in key.GetSubKeyNames())
                {
                    try
                    {
                        using var subKey = key.OpenSubKey(subKeyName);
                        var name = subKey?.GetValue("DisplayName")?.ToString();
                        if (string.IsNullOrEmpty(name)) continue;
                        var version = subKey?.GetValue("DisplayVersion")?.ToString() ?? "";
                        var publisher = subKey?.GetValue("Publisher")?.ToString() ?? "";
                        var installDate = subKey?.GetValue("InstallDate")?.ToString() ?? "";

                        // Skip system components and updates
                        if (name.StartsWith("KB") || name.Contains("Update for") ||
                            name.Contains("Security Update") || name.Contains("Hotfix"))
                            continue;

                        software.Add(new
                        {
                            name = name,
                            version = version,
                            publisher = publisher,
                            installDate = installDate
                        });
                    }
                    catch { }
                }
            }
            return software.DistinctBy(s => ((dynamic)s).name.ToString()).OrderBy(s => ((dynamic)s).name.ToString()).ToList();
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            Stop();
            _http?.Dispose();
        }

        // Response model for heartbeat
        private class HeartbeatResponse
        {
            public bool Ok { get; set; }
            public List<ConfigChange>? PendingConfig { get; set; }
            public string? Command { get; set; }
            public string? CustomerName { get; set; }
        }

        private class ConfigChange
        {
            public int Id { get; set; }
            public string Key { get; set; } = "";
            public string Value { get; set; } = "";
        }
    }
}
