namespace PCPlus.Core.Interfaces
{
    /// <summary>
    /// Service-wide configuration interface.
    /// Loaded from ProgramData/PCPlusEndpoint/config.json
    /// </summary>
    public interface IServiceConfig
    {
        // Identity
        string CompanyName { get; }
        string DeviceId { get; }
        string CustomerId { get; }

        // Monitoring thresholds
        float CpuAlertThreshold { get; }
        float RamAlertThreshold { get; }
        float DiskAlertThreshold { get; }
        float TempAlertThreshold { get; }
        int HealthPollIntervalMs { get; }

        // Ransomware settings
        bool RansomwareProtectionEnabled { get; }
        int HoneypotFileCount { get; }
        bool AutoContainmentEnabled { get; }
        bool LockdownOnDetection { get; }

        // Policy
        bool BlockUSB { get; }
        bool BlockPowerShell { get; }
        bool EnforceBitLocker { get; }

        // Alerts
        bool ShowBalloonAlerts { get; }
        bool LogAlerts { get; }
        bool SiemForwardingEnabled { get; }
        string SiemEndpoint { get; }

        // Licensing
        string LicenseKey { get; }
        string LicenseServerUrl { get; }
        LicenseTier ActiveTier { get; }

        // Integrations
        string TacticalRmmUrl { get; }
        string TacticalRmmApiKey { get; }
        string WazuhManagerUrl { get; }
        string MeshCentralUrl { get; }
        string DashboardApiUrl { get; }
        string DashboardApiToken { get; }

        // AI
        string AiProvider { get; } // "none", "local", "openai", "claude"
        string AiApiKey { get; }
        string AiModel { get; }

        // Support
        string ZammadUrl { get; }
        string ZammadApiToken { get; }
        string SupportPhone { get; }
        string SupportEmail { get; }
        string WebsiteUrl { get; }

        // Module enable/disable overrides
        Dictionary<string, bool> ModuleOverrides { get; }

        /// <summary>Reload config from disk.</summary>
        void Reload();

        /// <summary>Save current config to disk.</summary>
        void Save();

        /// <summary>Get a raw config value by key.</summary>
        string? GetValue(string key);

        /// <summary>Set a raw config value.</summary>
        void SetValue(string key, string value);
    }
}
