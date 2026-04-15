using PCPlus.Core.Interfaces;

namespace PCPlus.Core.Models
{
    /// <summary>Command sent from tray/dashboard to a module.</summary>
    public class ModuleCommand
    {
        public string ModuleId { get; set; } = "";
        public string Action { get; set; } = "";
        public Dictionary<string, string> Parameters { get; set; } = new();
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    }

    /// <summary>Response from a module after handling a command.</summary>
    public class ModuleResponse
    {
        public bool Success { get; set; }
        public string Message { get; set; } = "";
        public Dictionary<string, object> Data { get; set; } = new();

        public static ModuleResponse Ok(string message = "", Dictionary<string, object>? data = null) =>
            new() { Success = true, Message = message, Data = data ?? new() };

        public static ModuleResponse Fail(string message) =>
            new() { Success = false, Message = message };
    }

    /// <summary>Status report from a module.</summary>
    public class ModuleStatus
    {
        public string ModuleId { get; set; } = "";
        public string ModuleName { get; set; } = "";
        public bool IsRunning { get; set; }
        public string StatusText { get; set; } = "";
        public LicenseTier RequiredTier { get; set; }
        public DateTime LastActivity { get; set; }
        public Dictionary<string, object> Metrics { get; set; } = new();
    }

    /// <summary>Event broadcast between modules.</summary>
    public class ModuleEvent
    {
        public string SourceModule { get; set; } = "";
        public string EventType { get; set; } = "";
        public Dictionary<string, object> Data { get; set; } = new();
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;

        // Well-known event types
        public const string THREAT_DETECTED = "threat_detected";
        public const string LOCKDOWN_ACTIVATED = "lockdown_activated";
        public const string LOCKDOWN_DEACTIVATED = "lockdown_deactivated";
        public const string HEALTH_CRITICAL = "health_critical";
        public const string SECURITY_SCAN_COMPLETE = "security_scan_complete";
        public const string POLICY_VIOLATION = "policy_violation";
        public const string LICENSE_CHANGED = "license_changed";
        public const string CONFIG_CHANGED = "config_changed";
    }

    /// <summary>Alert raised by any module.</summary>
    public class Alert
    {
        public string Id { get; set; } = Guid.NewGuid().ToString("N")[..12];
        public string ModuleId { get; set; } = "";
        public string Title { get; set; } = "";
        public string Message { get; set; } = "";
        public AlertSeverity Severity { get; set; }
        public string Category { get; set; } = "";
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
        public bool Acknowledged { get; set; }
        public Dictionary<string, string> Metadata { get; set; } = new();
    }

    public enum AlertSeverity
    {
        Info = 0,
        Warning = 1,
        Critical = 2,
        Emergency = 3 // Ransomware / active threat
    }

    /// <summary>License validation result.</summary>
    public class LicenseInfo
    {
        public bool IsValid { get; set; }
        public LicenseTier Tier { get; set; } = LicenseTier.Free;
        public string CustomerId { get; set; } = "";
        public string DeviceId { get; set; } = "";
        public DateTime ExpiresAt { get; set; }
        public DateTime LastValidated { get; set; }
        public string[] EnabledFeatures { get; set; } = Array.Empty<string>();
        public string StatusMessage { get; set; } = "";
    }

    /// <summary>Audit log entry - every action gets logged.</summary>
    public class AuditEntry
    {
        public string Id { get; set; } = Guid.NewGuid().ToString("N")[..12];
        public string Module { get; set; } = "";
        public string Action { get; set; } = "";
        public string Detail { get; set; } = "";
        public string User { get; set; } = "";
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
        public Dictionary<string, string> Context { get; set; } = new();
    }
}
