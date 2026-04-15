using PCPlus.Core.Interfaces;
using PCPlus.Core.IPC;
using PCPlus.Core.Models;
using System.Text.Json;

namespace PCPlus.Service.Engine
{
    /// <summary>
    /// Core module engine. Loads, starts, stops, and manages all modules.
    /// Routes IPC requests to the appropriate module.
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
        private bool _disposed;

        public IServiceConfig Config => _config;
        public LicenseInfo License { get; set; } = new() { Tier = LicenseTier.Free, IsValid = true };
        public IAiAnalyzer? AiAnalyzer { get; set; }

        // Events
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

        /// <summary>Register a module (call before Start).</summary>
        public void RegisterModule(IModule module)
        {
            _modules[module.Id] = module;
        }

        /// <summary>Start the engine and all eligible modules.</summary>
        public async Task StartAsync(CancellationToken cancellationToken)
        {
            _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            Log(LogLevel.Info, "engine", $"Starting module engine v4.0.0 with {_modules.Count} modules");

            // Start IPC server
            _ipcServer.Start();
            Log(LogLevel.Info, "engine", "IPC server started");

            // Initialize and start each module
            foreach (var (id, module) in _modules)
            {
                // Check license tier
                if (module.RequiredTier > License.Tier)
                {
                    Log(LogLevel.Info, "engine",
                        $"Module '{id}' requires {module.RequiredTier} tier (current: {License.Tier}) - skipping");
                    continue;
                }

                // Check manual overrides
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

        /// <summary>Stop all modules and the engine.</summary>
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

            // Push to tray apps
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

        /// <summary>Push a health snapshot to all connected tray apps.</summary>
        public Task BroadcastHealthUpdateAsync(HealthSnapshot snapshot) =>
            _ipcServer.BroadcastAsync(IpcNotification.HEALTH_UPDATE, snapshot);

        // IPC request handler
        private async Task<IpcResponse> HandleIpcRequestAsync(IpcRequest request)
        {
            try
            {
                return request.Type switch
                {
                    IpcRequestType.Ping => IpcResponse.Ok(request.Id, "pong"),

                    IpcRequestType.GetServiceStatus => IpcResponse.Ok(request.Id,
                        GetServiceStatus()),

                    IpcRequestType.GetAllModuleStatuses => IpcResponse.Ok(request.Id,
                        _modules.Values.Select(m => m.GetStatus()).ToList()),

                    IpcRequestType.GetRecentAlerts => HandleGetAlerts(request),

                    IpcRequestType.AcknowledgeAlert => HandleAcknowledgeAlert(request),

                    IpcRequestType.GetLicenseInfo => IpcResponse.Ok(request.Id, License),

                    IpcRequestType.GetConfig => IpcResponse.Ok(request.Id,
                        _config.GetAllValues()),

                    IpcRequestType.SetConfig => HandleSetConfig(request),

                    // Module-specific requests - route to the appropriate module
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
                        await RouteToModuleAsync("ransomware", request),

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

        private IpcResponse HandleAcknowledgeAlert(IpcRequest request)
        {
            if (request.Parameters.TryGetValue("alertId", out var alertId))
            {
                lock (_alertLock)
                {
                    var alert = _alerts.FirstOrDefault(a => a.Id == alertId);
                    if (alert != null) alert.Acknowledged = true;
                }
            }
            return IpcResponse.Ok(request.Id);
        }

        private IpcResponse HandleSetConfig(IpcRequest request)
        {
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
            StartedAt = DateTime.UtcNow, // TODO: track actual start time
            Uptime = TimeSpan.FromMilliseconds(Environment.TickCount64),
            License = License,
            Modules = _modules.Values.Select(m => m.GetStatus()).ToList(),
            ActiveAlertCount = _alerts.Count(a => !a.Acknowledged),
            LockdownActive = false // Updated by ransomware module
        };

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            _ipcServer.Dispose();
            _cts?.Dispose();
        }
    }
}
