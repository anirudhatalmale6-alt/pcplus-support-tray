using System.Text.Json;
using System.Text.Json.Serialization;
using PCPlus.Core.Models;

namespace PCPlus.Core.IPC
{
    public static class IpcProtocol
    {
        public const string PIPE_NAME = "PCPlusEndpoint";

        public static readonly JsonSerializerOptions JsonOptions = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            WriteIndented = false
        };

        // Maximum request payload size (1MB) to prevent abuse
        public const int MAX_MESSAGE_SIZE = 1024 * 1024;

        // Session token validity
        public static readonly TimeSpan SESSION_TOKEN_LIFETIME = TimeSpan.FromHours(12);
    }

    /// <summary>
    /// Command permission levels. Each IPC request type has a required permission.
    /// Tray sessions get ReadOnly by default; Admin requires explicit authorization.
    /// </summary>
    public enum CommandPermission
    {
        ReadOnly,   // Get health, get status, ping - safe read operations
        Operator,   // Run scans, fix my computer - actions with no security impact
        Admin       // Lockdown, disable network, policy changes, config writes
    }

    /// <summary>Maps each request type to its required permission level.</summary>
    public static class CommandAuthorization
    {
        private static readonly Dictionary<IpcRequestType, CommandPermission> _permissions = new()
        {
            // ReadOnly - anyone can query these
            [IpcRequestType.Ping] = CommandPermission.ReadOnly,
            [IpcRequestType.GetServiceStatus] = CommandPermission.ReadOnly,
            [IpcRequestType.GetHealthSnapshot] = CommandPermission.ReadOnly,
            [IpcRequestType.GetHealthHistory] = CommandPermission.ReadOnly,
            [IpcRequestType.GetSecurityScore] = CommandPermission.ReadOnly,
            [IpcRequestType.GetSecurityReport] = CommandPermission.ReadOnly,
            [IpcRequestType.GetThreatStatus] = CommandPermission.ReadOnly,
            [IpcRequestType.GetLockdownState] = CommandPermission.ReadOnly,
            [IpcRequestType.GetModuleStatus] = CommandPermission.ReadOnly,
            [IpcRequestType.GetAllModuleStatuses] = CommandPermission.ReadOnly,
            [IpcRequestType.GetRecentAlerts] = CommandPermission.ReadOnly,
            [IpcRequestType.GetLicenseInfo] = CommandPermission.ReadOnly,
            [IpcRequestType.GetConfig] = CommandPermission.ReadOnly,
            [IpcRequestType.GetMaintenanceStatus] = CommandPermission.ReadOnly,

            // Operator - can trigger actions but nothing dangerous
            [IpcRequestType.RunSecurityScan] = CommandPermission.Operator,
            [IpcRequestType.RunMaintenance] = CommandPermission.Operator,
            [IpcRequestType.AcknowledgeAlert] = CommandPermission.Operator,
            [IpcRequestType.Authenticate] = CommandPermission.ReadOnly, // Auth itself is always allowed

            // Admin - dangerous operations requiring authorization
            [IpcRequestType.ActivateLockdown] = CommandPermission.Admin,
            [IpcRequestType.DeactivateLockdown] = CommandPermission.Admin,
            [IpcRequestType.SetConfig] = CommandPermission.Admin,
            [IpcRequestType.ActivateLicense] = CommandPermission.Admin,
            [IpcRequestType.SendModuleCommand] = CommandPermission.Operator, // Varies per module command
        };

        public static CommandPermission GetRequired(IpcRequestType type)
        {
            return _permissions.TryGetValue(type, out var perm) ? perm : CommandPermission.Admin;
        }

        /// <summary>Check if a session permission level satisfies the requirement.</summary>
        public static bool IsAuthorized(CommandPermission sessionLevel, CommandPermission required)
        {
            return (int)sessionLevel >= (int)required;
        }
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

        // Session authentication
        public string SessionToken { get; set; } = "";
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
        GetMaintenanceStatus,

        // Authentication
        Authenticate
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

        public static IpcResponse Unauthorized(string requestId, string message = "Insufficient permissions") => new()
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
        public const string SESSION_EXPIRED = "session_expired";

        public T? GetData<T>() where T : class
        {
            if (string.IsNullOrEmpty(JsonData)) return null;
            return JsonSerializer.Deserialize<T>(JsonData, IpcProtocol.JsonOptions);
        }
    }

    /// <summary>Session info returned after successful authentication.</summary>
    public class SessionInfo
    {
        public string Token { get; set; } = "";
        public CommandPermission PermissionLevel { get; set; }
        public DateTime ExpiresAt { get; set; }
        public string ClientIdentity { get; set; } = "";
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
