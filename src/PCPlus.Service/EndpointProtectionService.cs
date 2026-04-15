using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using PCPlus.Core.Licensing;
using PCPlus.Service.Engine;
using PCPlus.Service.Modules.Health;
using PCPlus.Service.Modules.Security;
using PCPlus.Service.Modules.Ransomware;
using PCPlus.Service.Modules.Maintenance;
using PCPlus.Service.Modules.Policy;

namespace PCPlus.Service
{
    /// <summary>
    /// The hosted service that runs as a Windows Service.
    /// Initializes the module engine, loads license, starts all modules.
    /// </summary>
    public class EndpointProtectionService : BackgroundService
    {
        private readonly ModuleEngine _engine;
        private readonly ServiceConfig _config;
        private readonly ILogger<EndpointProtectionService> _logger;

        public EndpointProtectionService(
            ModuleEngine engine,
            ServiceConfig config,
            ILogger<EndpointProtectionService> logger)
        {
            _engine = engine;
            _config = config;
            _logger = logger;

            _engine.OnLog += (module, msg) => _logger.LogInformation("[{Module}] {Message}", module, msg);
            _engine.OnAlert += alert =>
                _logger.LogWarning("[ALERT][{Module}] {Title}: {Message}",
                    alert.ModuleId, alert.Title, alert.Message);
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("PC Plus Endpoint Protection Service starting...");

            // Load and validate license
            var licenseManager = new LicenseManager();
            var license = licenseManager.LoadLicense();
            _engine.License = license;

            _logger.LogInformation("License: Tier={Tier}, Valid={Valid}, Device={DeviceId}",
                license.Tier, license.IsValid, LicenseManager.GenerateDeviceId()[..8] + "...");

            // Register all modules
            _engine.RegisterModule(new HealthModule());
            _engine.RegisterModule(new SecurityModule());
            _engine.RegisterModule(new RansomwareModule());
            _engine.RegisterModule(new MaintenanceModule());
            _engine.RegisterModule(new PolicyModule());

            // Start the engine (will start eligible modules based on license)
            await _engine.StartAsync(stoppingToken);

            _logger.LogInformation("PC Plus Endpoint Protection Service is running.");

            // Periodic license validation (every 6 hours)
            var licenseValidationTimer = new PeriodicTimer(TimeSpan.FromHours(6));
            try
            {
                while (await licenseValidationTimer.WaitForNextTickAsync(stoppingToken))
                {
                    if (!string.IsNullOrEmpty(_config.LicenseServerUrl))
                    {
                        var valid = await licenseManager.ValidateAsync();
                        _engine.License = licenseManager.CurrentLicense;
                        _logger.LogInformation("License validation: {Result}", valid ? "OK" : "Failed");
                    }
                }
            }
            catch (OperationCanceledException) { }

            // Stopping
            await _engine.StopAsync();
            _logger.LogInformation("PC Plus Endpoint Protection Service stopped.");
        }
    }
}
