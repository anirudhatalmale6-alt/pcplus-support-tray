namespace PCPlus.Core.Interfaces
{
    /// <summary>
    /// Base interface for all pluggable modules.
    /// Every feature (health, security, ransomware, etc.) implements this.
    /// Modules can be enabled/disabled per license tier.
    /// </summary>
    public interface IModule
    {
        /// <summary>Unique module identifier (e.g. "health", "ransomware", "security").</summary>
        string Id { get; }

        /// <summary>Display name for UI.</summary>
        string Name { get; }

        /// <summary>Module version.</summary>
        string Version { get; }

        /// <summary>Minimum license tier required (Free=0, Standard=1, Premium=2).</summary>
        LicenseTier RequiredTier { get; }

        /// <summary>Whether the module is currently active and running.</summary>
        bool IsRunning { get; }

        /// <summary>Initialize the module. Called once at service startup.</summary>
        Task InitializeAsync(IModuleContext context);

        /// <summary>Start the module's background work.</summary>
        Task StartAsync(CancellationToken cancellationToken);

        /// <summary>Stop the module gracefully.</summary>
        Task StopAsync();

        /// <summary>Handle a command from the tray app or dashboard.</summary>
        Task<ModuleResponse> HandleCommandAsync(ModuleCommand command);

        /// <summary>Get current module status for reporting.</summary>
        ModuleStatus GetStatus();
    }

    /// <summary>
    /// Context provided to modules during initialization.
    /// Gives modules access to shared services without tight coupling.
    /// </summary>
    public interface IModuleContext
    {
        /// <summary>Application configuration.</summary>
        IServiceConfig Config { get; }

        /// <summary>Send an alert to the alert pipeline.</summary>
        void RaiseAlert(Alert alert);

        /// <summary>Log a message.</summary>
        void Log(LogLevel level, string module, string message);

        /// <summary>Get another module by ID (for inter-module communication).</summary>
        IModule? GetModule(string moduleId);

        /// <summary>Broadcast an event to all modules.</summary>
        Task BroadcastEventAsync(ModuleEvent evt);

        /// <summary>Current license information.</summary>
        LicenseInfo License { get; }

        /// <summary>AI analysis interface (null if AI not configured).</summary>
        IAiAnalyzer? AiAnalyzer { get; }
    }

    public enum LicenseTier
    {
        Free = 0,
        Standard = 1,
        Premium = 2
    }

    public enum LogLevel
    {
        Debug,
        Info,
        Warning,
        Error,
        Critical
    }
}
