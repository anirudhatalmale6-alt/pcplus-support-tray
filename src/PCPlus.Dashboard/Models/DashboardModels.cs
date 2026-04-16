using System.ComponentModel.DataAnnotations;

namespace PCPlus.Dashboard.Models
{
    /// <summary>Registered endpoint device.</summary>
    public class Device
    {
        [Key]
        public string DeviceId { get; set; } = "";
        public string Hostname { get; set; } = "";
        public string CustomerId { get; set; } = "";
        public string CustomerName { get; set; } = "";
        public string OsVersion { get; set; } = "";
        public string AgentVersion { get; set; } = "";
        public string LicenseTier { get; set; } = "Free";
        public string LicenseKey { get; set; } = "";
        public string PolicyProfile { get; set; } = "default";
        public string IpAddress { get; set; } = "";
        public bool IsOnline { get; set; }
        public DateTime LastSeen { get; set; }
        public DateTime RegisteredAt { get; set; } = DateTime.UtcNow;

        // Latest health snapshot
        public float CpuPercent { get; set; }
        public float RamPercent { get; set; }
        public float DiskPercent { get; set; }
        public float CpuTempC { get; set; }
        public float GpuTempC { get; set; }
        public int HealthScore { get; set; }
        public int SecurityScore { get; set; }
        public string SecurityGrade { get; set; } = "?";
        public bool LockdownActive { get; set; }
        public int ActiveAlerts { get; set; }
        public int RunningModules { get; set; }
    }

    /// <summary>Alert received from an endpoint.</summary>
    public class DashboardAlert
    {
        [Key]
        public int Id { get; set; }
        public string DeviceId { get; set; } = "";
        public string Hostname { get; set; } = "";
        public string ModuleId { get; set; } = "";
        public string Title { get; set; } = "";
        public string Message { get; set; } = "";
        public string Severity { get; set; } = "Info";
        public string Category { get; set; } = "";
        public bool Acknowledged { get; set; }
        public string AcknowledgedBy { get; set; } = "";
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
        public Dictionary<string, string> Metadata { get; set; } = new();
    }

    /// <summary>Config push - queued config changes for an endpoint to pick up.</summary>
    public class ConfigPush
    {
        [Key]
        public int Id { get; set; }
        public string DeviceId { get; set; } = "";    // Empty = apply to all devices
        public string PolicyProfile { get; set; } = ""; // Empty = device-specific
        public string Key { get; set; } = "";
        public string Value { get; set; } = "";
        public bool Applied { get; set; }
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime? AppliedAt { get; set; }
        public string CreatedBy { get; set; } = "";
    }

    /// <summary>Incident record for history tracking.</summary>
    public class Incident
    {
        [Key]
        public int Id { get; set; }
        public string DeviceId { get; set; } = "";
        public string Hostname { get; set; } = "";
        public string Type { get; set; } = "";         // threat, lockdown, policy_violation
        public string Description { get; set; } = "";
        public string Severity { get; set; } = "";
        public string ActionsTaken { get; set; } = "";
        public bool Resolved { get; set; }
        public string ResolvedBy { get; set; } = "";
        public DateTime OccurredAt { get; set; } = DateTime.UtcNow;
        public DateTime? ResolvedAt { get; set; }
    }

    /// <summary>Policy profile - named set of config values.</summary>
    public class PolicyProfile
    {
        [Key]
        public string Name { get; set; } = "";
        public string Description { get; set; } = "";
        public string ConfigJson { get; set; } = "{}"; // JSON dictionary of config key-value pairs
        public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
        public string UpdatedBy { get; set; } = "";
    }

    /// <summary>Dashboard user/admin account.</summary>
    public class DashboardUser
    {
        [Key]
        public int Id { get; set; }
        public string Username { get; set; } = "";
        public string PasswordHash { get; set; } = "";
        public string Role { get; set; } = "viewer";  // admin, operator, viewer
        public string DisplayName { get; set; } = "";
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime LastLogin { get; set; }
        public string ApiToken { get; set; } = "";
    }

    // --- API request/response models ---

    /// <summary>Heartbeat sent by endpoints every 30 seconds.</summary>
    public class HeartbeatRequest
    {
        public string DeviceId { get; set; } = "";
        public string Hostname { get; set; } = "";
        public string CustomerName { get; set; } = "";
        public string OsVersion { get; set; } = "";
        public string AgentVersion { get; set; } = "";
        public string LicenseTier { get; set; } = "";
        public float CpuPercent { get; set; }
        public float RamPercent { get; set; }
        public float DiskPercent { get; set; }
        public float CpuTempC { get; set; }
        public float GpuTempC { get; set; }
        public int SecurityScore { get; set; }
        public string SecurityGrade { get; set; } = "";
        public bool LockdownActive { get; set; }
        public int ActiveAlerts { get; set; }
        public int RunningModules { get; set; }
        public List<ModuleStatusReport> Modules { get; set; } = new();
    }

    public class ModuleStatusReport
    {
        public string ModuleId { get; set; } = "";
        public string ModuleName { get; set; } = "";
        public bool IsRunning { get; set; }
        public string StatusText { get; set; } = "";
        public Dictionary<string, object> Metrics { get; set; } = new();
    }

    /// <summary>Response to heartbeat - may include pending config changes.</summary>
    public class HeartbeatResponse
    {
        public bool Ok { get; set; } = true;
        public List<ConfigChange> PendingConfig { get; set; } = new();
        public string? Command { get; set; }  // Optional command: "rescan", "lockdown", "restart"
    }

    public class ConfigChange
    {
        public int Id { get; set; }
        public string Key { get; set; } = "";
        public string Value { get; set; } = "";
    }

    /// <summary>Alert report from endpoint.</summary>
    public class AlertReport
    {
        public string DeviceId { get; set; } = "";
        public string Hostname { get; set; } = "";
        public string ModuleId { get; set; } = "";
        public string Title { get; set; } = "";
        public string Message { get; set; } = "";
        public string Severity { get; set; } = "";
        public string Category { get; set; } = "";
        public Dictionary<string, string> Metadata { get; set; } = new();
    }

    /// <summary>Dashboard overview statistics.</summary>
    public class DashboardOverview
    {
        public int TotalDevices { get; set; }
        public int OnlineDevices { get; set; }
        public int OfflineDevices { get; set; }
        public int ActiveAlerts { get; set; }
        public int CriticalAlerts { get; set; }
        public int DevicesInLockdown { get; set; }
        public int OpenIncidents { get; set; }
        public float AvgSecurityScore { get; set; }
        public float AvgHealthScore { get; set; }
        public Dictionary<string, int> DevicesByTier { get; set; } = new();
    }
}
