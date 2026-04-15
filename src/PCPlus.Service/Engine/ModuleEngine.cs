using PCPlus.Core.Interfaces;
using PCPlus.Core.IPC;
using PCPlus.Core.Models;
using System.Security.Principal;
using System.Text.Json;

namespace PCPlus.Service.Engine
{
    /// <summary>
    /// Core module engine. Loads, starts, stops, and manages all modules.
    /// Routes IPC requests with session auth and command authorization.
    /// Handles inter-module events and alert pipeline.
    /// </summary>
    public class ModuleEngine : IModuleContext, IDisposable
    {
        private readonly Dictionary<string, IModule> _modules = new();
        private readonly List<Alert> _alerts = new();
        private readonly object _alertLock = new();
        private readonly IpcServer _ipcServer;
        private readonly ServiceConfig _config;
        private readonly AuditLogger _auditLogger;
        private CancellationTokenSource? _cts;
        private DateTime _startedAt;
        private bool _disposed;

        public IServiceConfig Config => _config;
        public LicenseInfo License { get; set; } = new() { Tier = LicenseTier.Free, IsValid = true };
        public IAiAnalyzer? AiAnalyzer { get; set; }

        public event Action<Alert>? OnAlert;
        public event Action<string, string>? OnLog;

        public ModuleEngine(ServiceConfig config)
        {
            _config = config;
            _ipcServer = new IpcServer();
            _ipcServer.OnRequest += HandleIpcRequestAsync;

            _auditLogger = new AuditLogger(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "PCPlusEndpoint", "Logs"));
        }

        public void RegisterModule(IModule module)
        {
            _modules[module.Id] = module;
        }

        public async Task StartAsync(CancellationToken cancellationToken)
        {
            _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            _startedAt = DateTime.UtcNow;
            Log(LogLevel.Info, "engine", $"Starting module engine v4.0.0 with {_modules.Count} modules");

            _ipcServer.Start();
            Log(LogLevel.Info, "engine", "IPC server started (secured: session auth + command authorization)");

            foreach (var (id, module) in _modules)
            {
                if (module.RequiredTier > License.Tier)
                {
                    Log(LogLevel.Info, "engine",
                        $"Module '{id}' requires {module.RequiredTier} tier (current: {License.Tier}) - skipping");
                    continue;
                }

                if (_config.ModuleOverrides.TryGetValue(id, out var enabled) && !enabled)
                {
                    Log(LogLevel.Info, "engine", $"Module '{id}' disabled by config override - skipping");
                    continue;
                }

                try
                {
                    await module.InitializeAsync(this);
                    await module.StartAsync(_cts.Token);
                    Log(LogLevel.Info, "engine", $"Module '{id}' ({module.Name} v{module.Version}) started");
                    _auditLogger.Log("engine", "module_started", $"Module {id} started");
                }
                catch (Exception ex)
                {
                    Log(LogLevel.Error, "engine", $"Failed to start module '{id}': {ex.Message}");
                }
            }

            Log(LogLevel.Info, "engine",
                $"Engine started. {_modules.Values.Count(m => m.IsRunning)} modules running.");
        }

        public async Task StopAsync()
        {
            Log(LogLevel.Info, "engine", "Stopping module engine");

            foreach (var (id, module) in _modules)
            {
                if (module.IsRunning)
                {
                    try
                    {
                        await module.StopAsync();
                        Log(LogLevel.Info, "engine", $"Module '{id}' stopped");
                    }
                    catch (Exception ex)
                    {
                        Log(LogLevel.Error, "engine", $"Error stopping module '{id}': {ex.Message}");
                    }
                }
            }

            _ipcServer.Stop();
            _cts?.Cancel();
            Log(LogLevel.Info, "engine", "Engine stopped");
        }

        // IModuleContext implementation
        public void RaiseAlert(Alert alert)
        {
            lock (_alertLock)
            {
                _alerts.Add(alert);
                while (_alerts.Count > 500) _alerts.RemoveAt(0);
            }

            OnAlert?.Invoke(alert);
            _auditLogger.Log(alert.ModuleId, "alert",
                $"[{alert.Severity}] {alert.Title}: {alert.Message}");

            _ = _ipcServer.BroadcastAsync(IpcNotification.ALERT, alert);
        }

        public void Log(LogLevel level, string module, string message)
        {
            OnLog?.Invoke(module, $"[{level}] {message}");
            if (level >= LogLevel.Warning)
                _auditLogger.Log(module, "log", $"[{level}] {message}");
        }

        public IModule? GetModule(string moduleId)
        {
            _modules.TryGetValue(moduleId, out var module);
            return module;
        }

        public async Task BroadcastEventAsync(ModuleEvent evt)
        {
            foreach (var (_, module) in _modules)
            {
                if (module.IsRunning && module.Id != evt.SourceModule)
                {
                    try
                    {
                        await module.HandleCommandAsync(new ModuleCommand
                        {
                            ModuleId = module.Id,
                            Action = "event",
                            Parameters = new Dictionary<string, string>
                            {
                                ["eventType"] = evt.EventType,
                                ["sourceModule"] = evt.SourceModule,
                                ["data"] = JsonSerializer.Serialize(evt.Data)
                            }
                        });
                    }
                    catch { }
                }
            }
        }

        public Task BroadcastHealthUpdateAsync(HealthSnapshot snapshot) =>
            _ipcServer.BroadcastAsync(IpcNotification.HEALTH_UPDATE, snapshot);

        // IPC request handler - now with session context
        private async Task<IpcResponse> HandleIpcRequestAsync(IpcRequest request, IpcServer.ClientSession? session)
        {
            try
            {
                // Handle authentication first (no session needed)
                if (request.Type == IpcRequestType.Authenticate)
                    return HandleAuthenticate(request);

                return request.Type switch
                {
                    IpcRequestType.Ping => IpcResponse.Ok(request.Id, "pong"),

                    IpcRequestType.GetServiceStatus => IpcResponse.Ok(request.Id,
                        GetServiceStatus()),

                    IpcRequestType.GetAllModuleStatuses => IpcResponse.Ok(request.Id,
                        _modules.Values.Select(m => m.GetStatus()).ToList()),

                    IpcRequestType.GetRecentAlerts => HandleGetAlerts(request),

                    IpcRequestType.AcknowledgeAlert => HandleAcknowledgeAlert(request, session),

                    IpcRequestType.GetLicenseInfo => IpcResponse.Ok(request.Id, License),

                    IpcRequestType.GetConfig => IpcResponse.Ok(request.Id,
                        _config.GetAllValues()),

                    IpcRequestType.SetConfig => HandleSetConfig(request, session),

                    IpcRequestType.GetHealthSnapshot or
                    IpcRequestType.GetHealthHistory =>
                        await RouteToModuleAsync("health", request),

                    IpcRequestType.GetSecurityScore or
                    IpcRequestType.RunSecurityScan or
                    IpcRequestType.GetSecurityReport =>
                        await RouteToModuleAsync("security", request),

                    IpcRequestType.GetThreatStatus or
                    IpcRequestType.GetLockdownState or
                    IpcRequestType.ActivateLockdown or
                    IpcRequestType.DeactivateLockdown =>
                        await HandleRansomwareRequest(request, session),

                    IpcRequestType.RunMaintenance or
                    IpcRequestType.GetMaintenanceStatus =>
                        await RouteToModuleAsync("maintenance", request),

                    IpcRequestType.SendModuleCommand =>
                        await RouteToModuleAsync(request.ModuleId, request),

                    _ => IpcResponse.Fail(request.Id, $"Unknown request type: {request.Type}")
                };
            }
            catch (Exception ex)
            {
                return IpcResponse.Fail(request.Id, $"Error: {ex.Message}");
            }
        }

        private IpcResponse HandleAuthenticate(IpcRequest request)
        {
            var clientType = request.Parameters.GetValueOrDefault("clientType", "unknown");
            var user = request.Parameters.GetValueOrDefault("user", "unknown");
            var machine = request.Parameters.GetValueOrDefault("machine", "unknown");
            var clientIdentity = $"{user}@{machine} ({clientType})";

            // Determine permission level based on client type and user
            CommandPermission permLevel;
            if (clientType == "dashboard" || clientType == "admin")
            {
                // Dashboard/admin clients get full access
                permLevel = CommandPermission.Admin;
            }
            else
            {
                // Tray clients get Operator level (can run scans, maintenance, but not lockdown/config)
                // Check if user is a local admin for elevated permissions
                permLevel = IsLocalAdmin(user)
                    ? CommandPermission.Admin
                    : CommandPermission.Operator;
            }

            var session = _ipcServer.CreateSession(clientIdentity, permLevel);

            _auditLogger.Log("engine", "auth",
                $"Session created for {clientIdentity} with {permLevel} permissions");
            Log(LogLevel.Info, "engine", $"Client authenticated: {clientIdentity} [{permLevel}]");

            return IpcResponse.Ok(request.Id, session, "Authenticated");
        }

        private async Task<IpcResponse> HandleRansomwareRequest(IpcRequest request, IpcServer.ClientSession? session)
        {
            // Lockdown activation/deactivation are admin-only (already checked by server)
            // but we add audit logging here
            if (request.Type == IpcRequestType.ActivateLockdown ||
                request.Type == IpcRequestType.DeactivateLockdown)
            {
                _auditLogger.Log("engine", "security",
                    $"[{session?.ClientIdentity ?? "unknown"}] {request.Type} requested");
            }
            return await RouteToModuleAsync("ransomware", request);
        }

        private async Task<IpcResponse> RouteToModuleAsync(string moduleId, IpcRequest request)
        {
            if (!_modules.TryGetValue(moduleId, out var module))
                return IpcResponse.Fail(request.Id, $"Module '{moduleId}' not found");

            if (!module.IsRunning)
                return IpcResponse.Fail(request.Id, $"Module '{moduleId}' is not running");

            var command = new ModuleCommand
            {
                ModuleId = moduleId,
                Action = request.Type.ToString(),
                Parameters = request.Parameters
            };

            var result = await module.HandleCommandAsync(command);
            if (result.Success)
                return IpcResponse.Ok(request.Id, result.Data, result.Message);
            else
                return IpcResponse.Fail(request.Id, result.Message);
        }

        private IpcResponse HandleGetAlerts(IpcRequest request)
        {
            var count = 20;
            if (request.Parameters.TryGetValue("count", out var countStr))
                int.TryParse(countStr, out count);

            List<Alert> alerts;
            lock (_alertLock)
            {
                alerts = _alerts.TakeLast(count).Reverse().ToList();
            }
            return IpcResponse.Ok(request.Id, alerts);
        }

        private IpcResponse HandleAcknowledgeAlert(IpcRequest request, IpcServer.ClientSession? session)
        {
            if (request.Parameters.TryGetValue("alertId", out var alertId))
            {
                lock (_alertLock)
                {
                    var alert = _alerts.FirstOrDefault(a => a.Id == alertId);
                    if (alert != null)
                    {
                        alert.Acknowledged = true;
                        _auditLogger.Log("engine", "alert_ack",
                            $"Alert {alertId} acknowledged by {session?.ClientIdentity ?? "unknown"}");
                    }
                }
            }
            return IpcResponse.Ok(request.Id);
        }

        private IpcResponse HandleSetConfig(IpcRequest request, IpcServer.ClientSession? session)
        {
            _auditLogger.Log("engine", "config_change",
                $"Config updated by {session?.ClientIdentity ?? "unknown"}: " +
                string.Join(", ", request.Parameters.Select(p => $"{p.Key}={p.Value}")));

            foreach (var (key, value) in request.Parameters)
            {
                _config.SetValue(key, value);
            }
            _config.Save();
            _ = BroadcastEventAsync(new ModuleEvent
            {
                SourceModule = "engine",
                EventType = ModuleEvent.CONFIG_CHANGED
            });
            return IpcResponse.Ok(request.Id, "Config updated");
        }

        private ServiceStatusReport GetServiceStatus() => new()
        {
            Version = "4.0.0",
            IsRunning = true,
            StartedAt = _startedAt,
            Uptime = DateTime.UtcNow - _startedAt,
            License = License,
            Modules = _modules.Values.Select(m => m.GetStatus()).ToList(),
            ActiveAlertCount = _alerts.Count(a => !a.Acknowledged),
            LockdownActive = _modules.TryGetValue("ransomware", out var rm)
                && rm.IsRunning && rm.GetStatus().Metrics.TryGetValue("lockdownActive", out var la)
                && la is true
        };

        private static bool IsLocalAdmin(string username)
        {
            try
            {
                // Check if the user is in the Administrators group
                var identity = new WindowsIdentity(username);
                var principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            _ipcServer.Dispose();
            _cts?.Dispose();
        }
    }
}
