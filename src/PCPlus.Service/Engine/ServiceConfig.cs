using System.Text.Json;
using PCPlus.Core.Interfaces;

namespace PCPlus.Service.Engine
{
    /// <summary>
    /// Service configuration loaded from ProgramData/PCPlusEndpoint/config.json.
    /// Implements IServiceConfig for module access.
    /// </summary>
    public class ServiceConfig : IServiceConfig
    {
        private Dictionary<string, string> _values = new(StringComparer.OrdinalIgnoreCase);
        private static readonly string ConfigDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "PCPlusEndpoint");
        private static readonly string ConfigFile = Path.Combine(ConfigDir, "config.json");

        // Identity
        public string CompanyName => Get("companyName", "PC Plus Computing");
        public string DeviceId => Get("deviceId", "");
        public string CustomerId => Get("customerId", "");

        // Monitoring
        public float CpuAlertThreshold => GetFloat("cpuAlertThreshold", 90f);
        public float RamAlertThreshold => GetFloat("ramAlertThreshold", 90f);
        public float DiskAlertThreshold => GetFloat("diskAlertThreshold", 90f);
        public float TempAlertThreshold => GetFloat("tempAlertThreshold", 85f);
        public int HealthPollIntervalMs => GetInt("healthPollIntervalMs", 2000);

        // Ransomware
        public bool RansomwareProtectionEnabled => GetBool("ransomwareProtectionEnabled", true);
        public int HoneypotFileCount => GetInt("honeypotFileCount", 5);
        public bool AutoContainmentEnabled => GetBool("autoContainmentEnabled", true);
        public bool LockdownOnDetection => GetBool("lockdownOnDetection", true);

        // Behavior scoring weights
        public int ScoreHoneypotTriggered => GetInt("scoreHoneypotTriggered", 50);
        public int ScoreKnownRansomware => GetInt("scoreKnownRansomware", 50);
        public int ScoreShadowCopyDeletion => GetInt("scoreShadowCopyDeletion", 40);
        public int ScoreRansomNoteCreation => GetInt("scoreRansomNoteCreation", 35);
        public int ScoreMultiFolderTouch => GetInt("scoreMultiFolderTouch", 25);
        public int ScoreMassExtensionChange => GetInt("scoreMassExtensionChange", 20);
        public int ScoreSuspiciousPowerShell => GetInt("scoreSuspiciousPowerShell", 20);
        public int ScoreHighFileRenameRate => GetInt("scoreHighFileRenameRate", 20);
        public int ScoreHighEntropyWrite => GetInt("scoreHighEntropyWrite", 15);
        public int ScoreSuspiciousParentChild => GetInt("scoreSuspiciousParentChild", 15);
        public int ScoreRiskyLaunchPath => GetInt("scoreRiskyLaunchPath", 10);
        public int ScoreRansomwareExtension => GetInt("scoreRansomwareExtension", 10);
        public int ScoreFileRename => GetInt("scoreFileRename", 5);
        public int ScoreUnsignedProcess => GetInt("scoreUnsignedProcess", 5);

        // Behavior scoring thresholds
        public int ScoringWarningThreshold => GetInt("scoringWarningThreshold", 30);
        public int ScoringContainmentThreshold => GetInt("scoringContainmentThreshold", 60);
        public int ScoringLockdownThreshold => GetInt("scoringLockdownThreshold", 80);
        public int ScoringDecayPerMinute => GetInt("scoringDecayPerMinute", 5);

        // Policy
        public bool BlockUSB => GetBool("blockUSB", false);
        public bool BlockPowerShell => GetBool("blockPowerShell", false);
        public bool EnforceBitLocker => GetBool("enforceBitLocker", false);

        // Alerts
        public bool ShowBalloonAlerts => GetBool("showBalloonAlerts", true);
        public bool LogAlerts => GetBool("logAlerts", true);
        public bool SiemForwardingEnabled => GetBool("siemForwardingEnabled", false);
        public string SiemEndpoint => Get("siemEndpoint", "");

        // Licensing
        public string LicenseKey => Get("licenseKey", "");
        public string LicenseServerUrl => Get("licenseServerUrl", "");
        public LicenseTier ActiveTier => Enum.TryParse<LicenseTier>(Get("activeTier", "Free"), true, out var t) ? t : LicenseTier.Free;

        // Integrations
        public string TacticalRmmUrl => Get("tacticalRmmUrl", "https://rmm.pcpluscomputing.com");
        public string TacticalRmmApiKey => Get("tacticalRmmApiKey", "");
        public string WazuhManagerUrl => Get("wazuhManagerUrl", "");
        public string MeshCentralUrl => Get("meshCentralUrl", "https://mesh.pcpluscomputing.com");
        public string DashboardApiUrl => Get("dashboardApiUrl", "");
        public string DashboardApiToken => Get("dashboardApiToken", "");

        // AI
        public string AiProvider => Get("aiProvider", "none");
        public string AiApiKey => Get("aiApiKey", "");
        public string AiModel => Get("aiModel", "");

        // Support
        public string ZammadUrl => Get("zammadUrl", "https://support.pcpluscomputing.com");
        public string ZammadApiToken => Get("zammadApiToken", "");
        public string SupportPhone => Get("supportPhone", "16047601662");
        public string SupportEmail => Get("supportEmail", "pcpluscomputing@gmail.com");
        public string WebsiteUrl => Get("websiteUrl", "https://pcpluscomputing.com");

        // Module overrides
        public Dictionary<string, bool> ModuleOverrides
        {
            get
            {
                var overrides = new Dictionary<string, bool>();
                foreach (var (key, value) in _values)
                {
                    if (key.StartsWith("module.", StringComparison.OrdinalIgnoreCase))
                    {
                        var moduleId = key["module.".Length..];
                        if (bool.TryParse(value, out var enabled))
                            overrides[moduleId] = enabled;
                    }
                }
                return overrides;
            }
        }

        public static ServiceConfig Load()
        {
            var config = new ServiceConfig();
            config.Reload();
            return config;
        }

        public void Reload()
        {
            try
            {
                if (File.Exists(ConfigFile))
                {
                    var json = File.ReadAllText(ConfigFile);
                    var dict = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(json);
                    if (dict != null)
                    {
                        _values.Clear();
                        foreach (var (key, value) in dict)
                        {
                            _values[key] = value.ToString();
                        }
                    }
                }
            }
            catch { }
        }

        public void Save()
        {
            try
            {
                Directory.CreateDirectory(ConfigDir);
                var json = JsonSerializer.Serialize(_values, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(ConfigFile, json);
            }
            catch { }
        }

        public string? GetValue(string key)
        {
            _values.TryGetValue(key, out var value);
            return value;
        }

        public void SetValue(string key, string value)
        {
            _values[key] = value;
        }

        public Dictionary<string, string> GetAllValues() => new(_values);

        // Helper methods
        private string Get(string key, string defaultValue)
        {
            return _values.TryGetValue(key, out var v) ? v : defaultValue;
        }

        private float GetFloat(string key, float defaultValue)
        {
            return _values.TryGetValue(key, out var v) && float.TryParse(v, out var f) ? f : defaultValue;
        }

        private int GetInt(string key, int defaultValue)
        {
            return _values.TryGetValue(key, out var v) && int.TryParse(v, out var i) ? i : defaultValue;
        }

        private bool GetBool(string key, bool defaultValue)
        {
            return _values.TryGetValue(key, out var v) && bool.TryParse(v, out var b) ? b : defaultValue;
        }
    }
}
