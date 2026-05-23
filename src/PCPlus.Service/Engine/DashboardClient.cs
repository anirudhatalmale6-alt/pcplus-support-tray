using System.Diagnostics;
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
        private static readonly HttpClient _ipClient = new() { Timeout = TimeSpan.FromSeconds(5) };
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
                Timeout = TimeSpan.FromSeconds(30)
            };

            var token = _config.DashboardApiToken;
            if (!string.IsNullOrEmpty(token))
                _http.DefaultRequestHeaders.Add("X-Api-Token", token);

            // Subscribe to alerts to forward them to dashboard
            _engine.OnAlert += ForwardAlert;

            // Start heartbeat timer (configurable, default 30 seconds)
            var hbInterval = TimeSpan.FromSeconds(_config.GetValue("heartbeatIntervalSeconds") is string hv && int.TryParse(hv, out var hs) ? hs : 30);
            _heartbeatTimer = new Timer(SendHeartbeat, null, TimeSpan.Zero, hbInterval);

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

                // Get policy enforcement status
                var policyModule = _engine.GetModule("policy");
                int activeRules = 0, policyViolations = 0;
                if (policyModule?.IsRunning == true)
                {
                    var pStatus = policyModule.GetStatus();
                    if (pStatus.Metrics.TryGetValue("activeRules", out var arObj))
                        activeRules = Convert.ToInt32(arObj);
                    if (pStatus.Metrics.TryGetValue("violations24h", out var pvObj))
                        policyViolations = Convert.ToInt32(pvObj);
                }

                // Get customer value module status
                var cvModule = _engine.GetModule("customervalue");
                int wifiNetworks = 0, unsecureWifi = 0;
                string connectedSsid = "";
                if (cvModule?.IsRunning == true)
                {
                    var cvStatus = cvModule.GetStatus();
                    if (cvStatus.Metrics.TryGetValue("wifiNetworks", out var wnObj))
                        wifiNetworks = Convert.ToInt32(wnObj);
                    if (cvStatus.Metrics.TryGetValue("unsecureNetworks", out var uwObj))
                        unsecureWifi = Convert.ToInt32(uwObj);
                    if (cvStatus.Metrics.TryGetValue("connectedSsid", out var ssidObj))
                        connectedSsid = ssidObj?.ToString() ?? "";
                }

                // Count running modules
                var runningCount = _engine.GetAllModules().Count(m => m.IsRunning);

                // Get local IP
                var localIp = GetLocalIpAddress();

                // Get public IP (cached, refreshed every 5 minutes)
                var publicIp = await GetPublicIpAddress();

                // Collect software inventory and BitLocker keys every 10th heartbeat (~5 minutes)
                _heartbeatCount++;
                var installedSoftware = new List<object>();
                List<object>? bitlockerKeys = null;
                if (_heartbeatCount % 10 == 1)
                {
                    try { installedSoftware = CollectSoftwareInventory(); } catch { }
                    try { bitlockerKeys = CollectBitLockerRecoveryKeys(); } catch { }
                    // Send enrichment data (AV, backup, network, ransomware) to new endpoints
                    _ = Task.Run(async () => { try { await SendEnrichmentData(); } catch { } });
                }

                var heartbeat = new
                {
                    deviceId = _config.DeviceId,
                    hostname = Environment.MachineName,
                    osVersion = GetFriendlyOsVersion(),
                    agentVersion = typeof(DashboardClient).Assembly.GetName().Version?.ToString(3) ?? "4.3.0",
                    licenseTier = _engine.License.Tier.ToString(),
                    customerName = _config.CompanyName,
                    deviceGroup = _config.DeviceGroup,
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
                    installedSoftware = installedSoftware.Count > 0 ? installedSoftware : null,
                    bitLockerRecoveryKeys = bitlockerKeys,
                    policyActiveRules = activeRules,
                    policyViolations24h = policyViolations,
                    wifiNetworks = wifiNetworks,
                    wifiUnsecure = unsecureWifi,
                    wifiConnectedSsid = connectedSsid
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

            WriteAlertToQueue(report);

            if (_http == null) return;
            try
            {
                await _http.PostAsJsonAsync("/api/endpoint/alert", report);
            }
            catch { }
        }

        private void WriteAlertToQueue(object alertReport)
        {
            try
            {
                var queueDir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "PCPlusEndpoint", "alert-queue");
                Directory.CreateDirectory(queueDir);
                var fileName = $"alert_{DateTime.UtcNow:yyyyMMdd_HHmmss_fff}.json";
                File.WriteAllText(Path.Combine(queueDir, fileName),
                    JsonSerializer.Serialize(alertReport));
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

                case "restart-tray":
                    RestartTrayApp();
                    break;

                case "restart-service":
                    _engine.Log(LogLevel.Info, "dashboard-client", "Service restart requested from dashboard");
                    _ = Task.Run(async () =>
                    {
                        await Task.Delay(2000);
                        Environment.Exit(0);
                    });
                    break;

                case "update":
                    _engine.Log(LogLevel.Info, "dashboard-client", "Update check requested from dashboard");
                    break;
            }
        }

        private void RestartTrayApp()
        {
            try
            {
                foreach (var p in Process.GetProcessesByName("PCPlusTray"))
                {
                    p.Kill();
                    p.Dispose();
                }
                _engine.Log(LogLevel.Info, "dashboard-client", "Tray app killed - watchdog will restart it");
            }
            catch (Exception ex)
            {
                _engine.Log(LogLevel.Warning, "dashboard-client", $"Failed to restart tray: {ex.Message}");
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
                _cachedPublicIp = (await _ipClient.GetStringAsync("https://api.ipify.org")).Trim();
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

        private List<object> CollectBitLockerRecoveryKeys()
        {
            var keys = new List<object>();
            try
            {
                // Query BitLocker volumes via WMI
                using var searcher = new System.Management.ManagementObjectSearcher(
                    @"root\CIMV2\Security\MicrosoftVolumeEncryption",
                    "SELECT * FROM Win32_EncryptableVolume");
                foreach (System.Management.ManagementObject vol in searcher.Get())
                {
                    var driveLetter = vol["DriveLetter"]?.ToString() ?? "";
                    var protectionStatus = vol["ProtectionStatus"]?.ToString() ?? "0";

                    // Only capture keys for encrypted drives
                    if (protectionStatus == "0") continue;

                    try
                    {
                        // Get key protector IDs - use ManagementBaseObject for WMI method calls
                        var inParams = vol.GetMethodParameters("GetKeyProtectors");
                        inParams["KeyProtectorType"] = (uint)3; // 3 = Numerical Password
                        var outParams = vol.InvokeMethod("GetKeyProtectors", inParams, null);
                        if (outParams?["VolumeKeyProtectorID"] is string[] protectorIds)
                        {
                            foreach (var protectorId in protectorIds)
                            {
                                var keyInParams = vol.GetMethodParameters("GetKeyProtectorNumericalPassword");
                                keyInParams["VolumeKeyProtectorID"] = protectorId;
                                var keyOutParams = vol.InvokeMethod("GetKeyProtectorNumericalPassword", keyInParams, null);
                                var recoveryKey = keyOutParams?["NumericalPassword"]?.ToString() ?? "";
                                if (!string.IsNullOrEmpty(recoveryKey))
                                {
                                    keys.Add(new
                                    {
                                        driveLetter = driveLetter,
                                        keyProtectorId = protectorId,
                                        recoveryKey = recoveryKey
                                    });
                                }
                            }
                        }
                    }
                    catch { }
                }
            }
            catch { }
            return keys;
        }

        /// <summary>
        /// Sends enrichment data to the new dashboard endpoints every 10th heartbeat (~5 min).
        /// Covers: AV products, backup status, network security, ransomware status.
        /// </summary>
        private async Task SendEnrichmentData()
        {
            if (_http == null) return;
            var deviceId = _config.DeviceId;
            var hostname = Environment.MachineName;

            // 1. Antivirus products
            try
            {
                var products = CollectAntivirusProducts();
                if (products.Count > 0)
                {
                    await _http.PostAsJsonAsync("/api/endpoint/antivirus", new
                    {
                        deviceId,
                        products
                    });
                }
            }
            catch (Exception ex)
            {
                _engine.Log(LogLevel.Debug, "dashboard-client", $"AV enrichment failed: {ex.Message}");
            }

            // 2. Backup status
            try
            {
                var backup = CollectBackupStatus();
                if (backup != null)
                {
                    await _http.PostAsJsonAsync("/api/endpoint/backup-status", new
                    {
                        deviceId,
                        hostname,
                        provider = backup.Provider,
                        lastBackupTime = backup.LastBackupTime,
                        status = backup.Status,
                        sizeBytes = backup.SizeBytes,
                        protectedPaths = backup.ProtectedPaths,
                        shadowCopyEnabled = backup.ShadowCopyEnabled,
                        shadowCopyCount = backup.ShadowCopyCount,
                        recoveryPointCount = backup.RecoveryPointCount
                    });
                }
            }
            catch (Exception ex)
            {
                _engine.Log(LogLevel.Debug, "dashboard-client", $"Backup enrichment failed: {ex.Message}");
            }

            // 3. Network security
            try
            {
                var network = CollectNetworkSecurity();
                await _http.PostAsJsonAsync("/api/endpoint/network-security", new
                {
                    deviceId,
                    hostname,
                    firewallEnabled = network.FirewallEnabled,
                    firewallProfiles = network.FirewallProfiles,
                    openPorts = network.OpenPorts,
                    activeConnections = network.ActiveConnections,
                    rdpEnabled = network.RdpEnabled,
                    dnsServers = network.DnsServers,
                    wifiSecurityType = network.WifiSecurityType
                });
            }
            catch (Exception ex)
            {
                _engine.Log(LogLevel.Debug, "dashboard-client", $"Network enrichment failed: {ex.Message}");
            }

            // 4. Ransomware shield status
            try
            {
                var rwModule = _engine.GetModule("ransomware");
                if (rwModule?.IsRunning == true)
                {
                    var status = rwModule.GetStatus();
                    await _http.PostAsJsonAsync("/api/endpoint/ransomware-status", new
                    {
                        deviceId,
                        hostname,
                        behaviorMonitoringEnabled = status.Metrics.TryGetValue("behaviorMonitoring", out var bm) && Convert.ToBoolean(bm),
                        protectedFolders = GetProtectedFolders(),
                        shadowCopyProtected = IsShadowCopyProtected(),
                        honeypotActive = status.Metrics.TryGetValue("honeypotActive", out var hp) && Convert.ToBoolean(hp),
                        rollbackCapable = IsShadowCopyProtected(),
                        detectionRules = GetDetectionRules(),
                        threatHistory = new List<object>()
                    });
                }
            }
            catch (Exception ex)
            {
                _engine.Log(LogLevel.Debug, "dashboard-client", $"Ransomware enrichment failed: {ex.Message}");
            }

            _engine.Log(LogLevel.Debug, "dashboard-client", "Enrichment data sent");
        }

        private List<object> CollectAntivirusProducts()
        {
            var products = new List<object>();
            try
            {
                using var searcher = new System.Management.ManagementObjectSearcher(
                    "root\\SecurityCenter2", "SELECT * FROM AntiVirusProduct");
                foreach (System.Management.ManagementObject obj in searcher.Get())
                {
                    try
                    {
                        var name = obj["displayName"]?.ToString() ?? "";
                        if (string.IsNullOrEmpty(name)) continue;

                        var state = Convert.ToUInt32(obj["productState"]);
                        // Decode productState: bits 12-15 = scanner enabled, bits 4-7 = definition status
                        var scannerEnabled = ((state >> 12) & 0xF) == 1;
                        var defsOutdated = ((state >> 4) & 0xF) != 0;

                        // Determine Active vs Passive vs OnDemand
                        string status;
                        if (scannerEnabled && name.Contains("Defender", StringComparison.OrdinalIgnoreCase))
                        {
                            // If Defender + another AV is active, Defender is passive
                            status = products.Any(p => ((dynamic)p).status == "Active") ? "Passive" : "Active";
                        }
                        else if (scannerEnabled)
                        {
                            status = "Active";
                        }
                        else
                        {
                            status = "OnDemand";
                        }

                        // If a non-Defender product is active, mark Defender as Passive
                        if (status == "Active" && !name.Contains("Defender", StringComparison.OrdinalIgnoreCase))
                        {
                            for (int i = 0; i < products.Count; i++)
                            {
                                var p = (dynamic)products[i];
                                if (p.name.ToString().Contains("Defender") && p.status == "Active")
                                {
                                    products[i] = new
                                    {
                                        name = (string)p.name,
                                        vendor = (string)p.vendor,
                                        version = (string)p.version,
                                        definitionDate = (string)p.definitionDate,
                                        status = "Passive",
                                        realTimeEnabled = false,
                                        lastScanTime = (string)p.lastScanTime,
                                        quarantineCount = (int)p.quarantineCount
                                    };
                                }
                            }
                        }

                        products.Add(new
                        {
                            name,
                            vendor = name.Contains("Defender") ? "Microsoft" :
                                     name.Contains("Avast") ? "Avast" :
                                     name.Contains("AVG") ? "AVG" :
                                     name.Contains("Norton") ? "Norton" :
                                     name.Contains("McAfee") ? "McAfee" :
                                     name.Contains("Kaspersky") ? "Kaspersky" :
                                     name.Contains("Bitdefender") ? "Bitdefender" :
                                     name.Contains("ESET") ? "ESET" :
                                     name.Contains("Malwarebytes") ? "Malwarebytes" :
                                     name.Contains("Webroot") ? "Webroot" :
                                     name.Contains("Sophos") ? "Sophos" :
                                     name.Contains("Trend") ? "Trend Micro" : "Unknown",
                            version = "",
                            definitionDate = defsOutdated ? "" : DateTime.UtcNow.ToString("yyyy-MM-dd"),
                            status,
                            realTimeEnabled = scannerEnabled,
                            lastScanTime = "",
                            quarantineCount = 0
                        });
                    }
                    finally { obj.Dispose(); }
                }
            }
            catch { }
            return products;
        }

        private class BackupInfo
        {
            public string Provider { get; set; } = "";
            public string? LastBackupTime { get; set; }
            public string Status { get; set; } = "";
            public long SizeBytes { get; set; }
            public List<string> ProtectedPaths { get; set; } = new();
            public bool ShadowCopyEnabled { get; set; }
            public int ShadowCopyCount { get; set; }
            public int RecoveryPointCount { get; set; }
        }

        private BackupInfo? CollectBackupStatus()
        {
            var info = new BackupInfo();
            try
            {
                // Check File History
                var fhKey = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\FileHistory");
                if (fhKey != null)
                {
                    info.Provider = "WindowsFileHistory";
                    var protectedUpTo = fhKey.GetValue("ProtectedUpToTime");
                    if (protectedUpTo is long ft && ft > 0)
                    {
                        var lastBackup = DateTime.FromFileTimeUtc(ft);
                        info.LastBackupTime = lastBackup.ToString("o");
                        info.Status = (DateTime.UtcNow - lastBackup).TotalDays < 7 ? "Success" : "Overdue";
                    }
                    else
                    {
                        info.Status = "Success";
                    }
                }
                else
                {
                    // Check System Restore
                    var srKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                        @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore");
                    if (srKey != null)
                    {
                        var rpEnabled = Convert.ToInt32(srKey.GetValue("RPSessionInterval", 0));
                        if (rpEnabled > 0 || Convert.ToInt32(srKey.GetValue("DisableSR", 1)) == 0)
                        {
                            info.Provider = "SystemRestore";
                            info.Status = "Success";
                        }
                    }
                }

                // Check shadow copies
                try
                {
                    using var searcher = new System.Management.ManagementObjectSearcher(
                        "SELECT * FROM Win32_ShadowCopy");
                    var shadows = searcher.Get();
                    info.ShadowCopyCount = shadows.Count;
                    info.ShadowCopyEnabled = shadows.Count > 0;
                    info.RecoveryPointCount = shadows.Count;
                }
                catch { }

                // Protected paths (common backup locations)
                info.ProtectedPaths = new List<string>();
                var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                foreach (var folder in new[] { "Documents", "Desktop", "Pictures", "Downloads" })
                {
                    var path = Path.Combine(userProfile, folder);
                    if (Directory.Exists(path)) info.ProtectedPaths.Add(path);
                }

                if (!string.IsNullOrEmpty(info.Provider)) return info;
            }
            catch { }
            return null;
        }

        private class NetworkInfo
        {
            public bool FirewallEnabled { get; set; }
            public List<object> FirewallProfiles { get; set; } = new();
            public List<object> OpenPorts { get; set; } = new();
            public int ActiveConnections { get; set; }
            public bool RdpEnabled { get; set; }
            public List<string> DnsServers { get; set; } = new();
            public string WifiSecurityType { get; set; } = "N/A";
        }

        private NetworkInfo CollectNetworkSecurity()
        {
            var info = new NetworkInfo();
            try
            {
                // Check firewall profiles
                foreach (var profile in new[] { "DomainProfile", "StandardProfile", "PublicProfile" })
                {
                    using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                        $@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{profile}");
                    var enabled = key != null && Convert.ToInt32(key.GetValue("EnableFirewall", 0)) == 1;
                    info.FirewallProfiles.Add(new
                    {
                        name = profile.Replace("Profile", "").Replace("Standard", "Private"),
                        enabled,
                        defaultAction = "Block"
                    });
                    if (enabled) info.FirewallEnabled = true;
                }

                // Check RDP
                try
                {
                    using var rdpKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                        @"SYSTEM\CurrentControlSet\Control\Terminal Server");
                    info.RdpEnabled = rdpKey != null && Convert.ToInt32(rdpKey.GetValue("fDenyTSConnections", 1)) == 0;
                }
                catch { }

                // Get DNS servers
                try
                {
                    var adapters = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces();
                    foreach (var adapter in adapters.Where(a => a.OperationalStatus == System.Net.NetworkInformation.OperationalStatus.Up))
                    {
                        var dns = adapter.GetIPProperties().DnsAddresses;
                        foreach (var d in dns)
                        {
                            var addr = d.ToString();
                            if (!info.DnsServers.Contains(addr)) info.DnsServers.Add(addr);
                        }
                    }
                }
                catch { }

                // Count active TCP connections
                try
                {
                    var tcpStats = System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties();
                    info.ActiveConnections = tcpStats.GetActiveTcpConnections().Length;
                }
                catch { }

                // Get listening ports (top 20)
                try
                {
                    var tcpStats = System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties();
                    var listeners = tcpStats.GetActiveTcpListeners().Take(20);
                    info.OpenPorts = listeners.Select(l => (object)new
                    {
                        port = l.Port,
                        protocol = "TCP",
                        process = "",
                        state = "LISTENING"
                    }).ToList();
                }
                catch { }
            }
            catch { }
            return info;
        }

        private List<string> GetProtectedFolders()
        {
            var folders = new List<string>();
            try
            {
                // Check Controlled Folder Access (Windows Defender)
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access\ProtectedFolders");
                if (key != null)
                {
                    foreach (var name in key.GetValueNames())
                    {
                        folders.Add(name);
                    }
                }
            }
            catch { }

            // Default protected paths
            if (folders.Count == 0)
            {
                var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                foreach (var folder in new[] { "Documents", "Desktop", "Pictures", "Music", "Videos", "Downloads" })
                {
                    var path = Path.Combine(userProfile, folder);
                    if (Directory.Exists(path)) folders.Add(path);
                }
            }
            return folders;
        }

        private bool IsShadowCopyProtected()
        {
            try
            {
                using var searcher = new System.Management.ManagementObjectSearcher("SELECT * FROM Win32_ShadowCopy");
                return searcher.Get().Count > 0;
            }
            catch { return false; }
        }

        private List<object> GetDetectionRules()
        {
            return new List<object>
            {
                new { ruleName = "Honeypot File Monitoring", enabled = true, severity = "Critical" },
                new { ruleName = "Rapid File Encryption", enabled = true, severity = "Critical" },
                new { ruleName = "Known Ransomware Extensions", enabled = true, severity = "High" },
                new { ruleName = "Suspicious PowerShell", enabled = true, severity = "High" },
                new { ruleName = "Mass File Rename", enabled = true, severity = "High" },
                new { ruleName = "Parent-Child Process Anomaly", enabled = true, severity = "Medium" },
                new { ruleName = "Shadow Copy Deletion", enabled = true, severity = "Critical" },
                new { ruleName = "File Entropy Analysis", enabled = true, severity = "Medium" }
            };
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
