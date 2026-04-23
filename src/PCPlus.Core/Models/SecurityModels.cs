namespace PCPlus.Core.Models
{
    /// <summary>Result of a security scan.</summary>
    public class SecurityScanResult
    {
        public int TotalScore { get; set; }
        public string Grade { get; set; } = "?";
        public List<SecurityCheck> Checks { get; set; } = new();
        public DateTime ScanTime { get; set; }
    }

    public class SecurityCheck
    {
        public string Id { get; set; } = "";
        public string Name { get; set; } = "";
        public string Category { get; set; } = "";
        public string Description { get; set; } = "";
        public int Weight { get; set; }
        public bool Passed { get; set; }
        public string Detail { get; set; } = "";
        public string Recommendation { get; set; } = "";
        public DateTime LastChecked { get; set; } = DateTime.UtcNow;
    }

    /// <summary>Ransomware detection event.</summary>
    public class ThreatDetection
    {
        public string ThreatId { get; set; } = Guid.NewGuid().ToString("N")[..12];
        public ThreatType Type { get; set; }
        public string ProcessName { get; set; } = "";
        public string ProcessPath { get; set; } = "";
        public int ProcessId { get; set; }
        public string Description { get; set; } = "";
        public ThreatSeverity Severity { get; set; }
        public DateTime DetectedAt { get; set; } = DateTime.UtcNow;
        public string[] AffectedFiles { get; set; } = Array.Empty<string>();
        public string[] ActionsTaken { get; set; } = Array.Empty<string>();
        public bool Contained { get; set; }
    }

    public enum ThreatType
    {
        FileEncryption,         // Mass file encryption detected
        SuspiciousProcess,      // Unknown process doing dangerous things
        PowerShellAbuse,        // Encoded/obfuscated PowerShell execution
        ShadowCopyDeletion,     // vssadmin delete shadows
        RansomNote,             // Ransom note file created
        HoneypotTriggered,      // Decoy file was touched
        MassFileRename,         // Bulk file extension changes
        RegistryTampering,      // Suspicious registry modifications
        NetworkExfiltration,    // Unusual outbound data transfer
        PrivilegeEscalation,    // Unauthorized privilege elevation
        PolicyViolation         // Security policy breach
    }

    public enum ThreatSeverity
    {
        Low = 0,
        Medium = 1,
        High = 2,
        Critical = 3
    }

    /// <summary>System lockdown state.</summary>
    public class LockdownState
    {
        public bool IsActive { get; set; }
        public DateTime ActivatedAt { get; set; }
        public string Reason { get; set; } = "";
        public string TriggeredBy { get; set; } = "";
        public LockdownActions ActiveActions { get; set; } = new();
    }

    public class LockdownActions
    {
        public bool NetworkDisabled { get; set; }
        public bool UsbBlocked { get; set; }
        public bool ExecutablesBlocked { get; set; }
        public bool RdpDisabled { get; set; }
        public List<int> KilledProcessIds { get; set; } = new();
        public List<string> KilledProcessNames { get; set; } = new();
    }

    /// <summary>Policy rule definition.</summary>
    public class PolicyRule
    {
        public string Id { get; set; } = "";
        public string Name { get; set; } = "";
        public string Category { get; set; } = ""; // usb, powershell, bitlocker, network, etc.
        public PolicyAction Action { get; set; }
        public string Condition { get; set; } = "";
        public Dictionary<string, string> Parameters { get; set; } = new();
        public bool Enabled { get; set; } = true;
    }

    public enum PolicyAction
    {
        Alert,      // Just notify
        Block,      // Prevent the action
        AutoFix,    // Automatically remediate
        Audit       // Log only
    }
}
