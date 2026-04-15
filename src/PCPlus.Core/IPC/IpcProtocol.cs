using System.Text.Json;
using System.Text.Json.Serialization;
using PCPlus.Core.Models;

namespace PCPlus.Core.IPC
{
    /// <summary>
    /// IPC message protocol for communication between Tray App and Windows Service.
    /// Uses named pipes with JSON serialization.
    /// Pipe name: "PCPlusEndpoint"
    /// </summary>
    public static class IpcProtocol
    {
        public const string PIPE_NAME = "PCPlusEndpoint";

        public static readonly JsonSerializerOptions JsonOptions = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            WriteIndented = false
        };
    }

    /// <summary>Message sent from tray to service.</summary>
    public class IpcRequest
    {
        public string Id { get; set; } = Guid.NewGuid().ToString("N")[..8];
        public IpcRequestType Type { get; set; }
        public string ModuleId { get; set; } = "";
        public string Action { get; set; } = "";
        public Dictionary<string, string> Parameters { get; set; } = new();
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    }

    public enum IpcRequestType
    {
        // Health
        GetHealthSnapshot,
        GetHealthHistory,

        // Security
        GetSecurityScore,
        RunSecurityScan,
        GetSecurityReport,

        // Ransomware
        GetThreatStatus,
        GetLockdownState,
        ActivateLockdown,
        DeactivateLockdown,

        // Module management
        GetModuleStatus,
        GetAllModuleStatuses,
        SendModuleCommand,

        // Alerts
        GetRecentAlerts,
        AcknowledgeAlert,

        // License
        GetLicenseInfo,
        ActivateLicense,

        // System
        GetServiceStatus,
        Ping,

        // Config
        GetConfig,
        SetConfig,

        // Maintenance
        RunMaintenance,
        GetMaintenanceStatus
    }

    /// <summary>Message sent from service to tray.</summary>
    public class IpcResponse
    {
        public string RequestId { get; set; } = "";
        public bool Success { get; set; }
        public string Message { get; set; } = "";
        public string JsonData { get; set; } = ""; // Serialized payload
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;

        public T? GetData<T>() where T : class
        {
            if (string.IsNullOrEmpty(JsonData)) return null;
            return JsonSerializer.Deserialize<T>(JsonData, IpcProtocol.JsonOptions);
        }

        public static IpcResponse Ok<T>(string requestId, T data, string message = "") => new()
        {
            RequestId = requestId,
            Success = true,
            Message = message,
            JsonData = JsonSerializer.Serialize(data, IpcProtocol.JsonOptions)
        };

        public static IpcResponse Ok(string requestId, string message = "") => new()
        {
            RequestId = requestId,
            Success = true,
            Message = message
        };

        public static IpcResponse Fail(string requestId, string message) => new()
        {
            RequestId = requestId,
            Success = false,
            Message = message
        };
    }

    /// <summary>Push notification from service to tray (unsolicited).</summary>
    public class IpcNotification
    {
        public string Type { get; set; } = "";
        public string JsonData { get; set; } = "";
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;

        // Well-known notification types
        public const string HEALTH_UPDATE = "health_update";
        public const string ALERT = "alert";
        public const string THREAT_DETECTED = "threat_detected";
        public const string LOCKDOWN_CHANGED = "lockdown_changed";
        public const string MODULE_STATUS_CHANGED = "module_status_changed";
        public const string LICENSE_CHANGED = "license_changed";

        public T? GetData<T>() where T : class
        {
            if (string.IsNullOrEmpty(JsonData)) return null;
            return JsonSerializer.Deserialize<T>(JsonData, IpcProtocol.JsonOptions);
        }
    }

    /// <summary>
    /// Service status summary - returned on ping / dashboard overview.
    /// </summary>
    public class ServiceStatusReport
    {
        public string Version { get; set; } = "";
        public bool IsRunning { get; set; }
        public DateTime StartedAt { get; set; }
        public TimeSpan Uptime { get; set; }
        public LicenseInfo? License { get; set; }
        public List<ModuleStatus> Modules { get; set; } = new();
        public int ActiveAlertCount { get; set; }
        public bool LockdownActive { get; set; }
    }
}
