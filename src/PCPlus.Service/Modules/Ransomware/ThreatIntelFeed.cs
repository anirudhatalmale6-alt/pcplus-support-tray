using System.Collections.Concurrent;
using System.Text.Json;
using System.Text.Json.Serialization;
using PCPlus.Core.Interfaces;

namespace PCPlus.Service.Modules.Ransomware
{
    public class ThreatIntelFeed : IDisposable
    {
        private const string ModuleName = "threat-intel";
        private static readonly string DataDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "PCPlusEndpoint", "ransomware");
        private static readonly string PersistPath = Path.Combine(DataDir, "threat-intel.json");
        private static readonly string CustomIndicatorsPath = Path.Combine(DataDir, "custom-indicators.json");

        private static readonly TimeSpan UpdateInterval = TimeSpan.FromHours(12);
        private static readonly TimeSpan HttpTimeout = TimeSpan.FromSeconds(30);

        private readonly IModuleContext _context;
        private readonly HttpClient _http;
        private Timer? _updateTimer;
        private readonly object _lock = new();

        private HashSet<string> _knownExtensions;
        private HashSet<string> _knownRansomNotes;
        private HashSet<string> _knownProcessNames;
        private HashSet<string> _knownFileHashes;
        private ConcurrentDictionary<string, IndicatorOfCompromise> _iocs = new();

        private DateTime _lastUpdate = DateTime.MinValue;
        private readonly Dictionary<string, FeedHealth> _feedHealth = new();

        public event Action? OnIndicatorsUpdated;

        public ThreatIntelFeed(IModuleContext context)
        {
            _context = context;
            _http = new HttpClient { Timeout = HttpTimeout };
            _http.DefaultRequestHeaders.UserAgent.ParseAdd("PCPlusEndpoint/5.0");

            _knownExtensions = new HashSet<string>(BaseExtensions, StringComparer.OrdinalIgnoreCase);
            _knownRansomNotes = new HashSet<string>(BaseRansomNotes, StringComparer.OrdinalIgnoreCase);
            _knownProcessNames = new HashSet<string>(BaseProcessNames, StringComparer.OrdinalIgnoreCase);
            _knownFileHashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        }

        public void Start()
        {
            LoadPersistedData();
            _updateTimer = new Timer(_ => _ = UpdateAsync(), null, TimeSpan.Zero, UpdateInterval);
            _context.Log(LogLevel.Info, ModuleName, "Threat intelligence feed started");
        }

        public void Dispose()
        {
            _updateTimer?.Dispose();
            _http.Dispose();
        }

        // --- Query Methods ---

        public bool IsKnownExtension(string ext)
        {
            lock (_lock) return _knownExtensions.Contains(ext);
        }

        public bool IsKnownRansomNote(string filename)
        {
            lock (_lock) return _knownRansomNotes.Contains(filename);
        }

        public bool IsKnownProcess(string name)
        {
            lock (_lock) return _knownProcessNames.Contains(name);
        }

        public bool IsKnownHash(string sha256)
        {
            lock (_lock) return _knownFileHashes.Contains(sha256);
        }

        public ThreatIntelStatus GetStatus()
        {
            lock (_lock)
            {
                return new ThreatIntelStatus
                {
                    ExtensionCount = _knownExtensions.Count,
                    RansomNoteCount = _knownRansomNotes.Count,
                    ProcessNameCount = _knownProcessNames.Count,
                    FileHashCount = _knownFileHashes.Count,
                    IocCount = _iocs.Count,
                    LastUpdate = _lastUpdate,
                    FeedHealth = new Dictionary<string, FeedHealth>(_feedHealth)
                };
            }
        }

        public Task ForceUpdateAsync() => UpdateAsync();

        public void AddCustomIndicator(string type, string value)
        {
            if (string.IsNullOrWhiteSpace(type) || string.IsNullOrWhiteSpace(value))
                return;

            var normalizedType = type.ToLowerInvariant();
            lock (_lock)
            {
                switch (normalizedType)
                {
                    case "extension":
                        _knownExtensions.Add(value.StartsWith('.') ? value : "." + value);
                        break;
                    case "ransomnote":
                        _knownRansomNotes.Add(value);
                        break;
                    case "process":
                        _knownProcessNames.Add(value);
                        break;
                    case "hash":
                        _knownFileHashes.Add(value);
                        break;
                }

                _iocs[BuildIocKey(normalizedType, value)] = new IndicatorOfCompromise
                {
                    Type = normalizedType,
                    Value = value,
                    Source = "custom",
                    LastSeen = DateTime.UtcNow
                };
            }

            PersistData();
            SaveCustomIndicator(normalizedType, value);
            OnIndicatorsUpdated?.Invoke();

            _context.Log(LogLevel.Info, ModuleName, $"Custom indicator added: {type}={value}");
        }

        // --- Update Pipeline ---

        private async Task UpdateAsync()
        {
            _context.Log(LogLevel.Info, ModuleName, "Starting threat intelligence update...");

            var extensions = new HashSet<string>(BaseExtensions, StringComparer.OrdinalIgnoreCase);
            var ransomNotes = new HashSet<string>(BaseRansomNotes, StringComparer.OrdinalIgnoreCase);
            var processNames = new HashSet<string>(BaseProcessNames, StringComparer.OrdinalIgnoreCase);
            var fileHashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var iocs = new ConcurrentDictionary<string, IndicatorOfCompromise>();

            await Task.WhenAll(
                FetchAbuseCh(fileHashes, iocs),
                FetchThreatFox(extensions, ransomNotes, processNames, fileHashes, iocs),
                FetchDashboardFeed(extensions, ransomNotes, processNames, fileHashes, iocs)
            );

            LoadCustomIndicators(extensions, ransomNotes, processNames, fileHashes, iocs);

            lock (_lock)
            {
                _knownExtensions = extensions;
                _knownRansomNotes = ransomNotes;
                _knownProcessNames = processNames;
                _knownFileHashes = fileHashes;
                _iocs = iocs;
                _lastUpdate = DateTime.UtcNow;
            }

            PersistData();
            OnIndicatorsUpdated?.Invoke();

            var status = GetStatus();
            _context.Log(LogLevel.Info, ModuleName,
                $"Threat intel updated: {status.ExtensionCount} extensions, {status.RansomNoteCount} notes, " +
                $"{status.ProcessNameCount} processes, {status.FileHashCount} hashes, {status.IocCount} IOCs");
        }

        // --- Feed: abuse.ch Malware Hashes CSV ---

        private async Task FetchAbuseCh(HashSet<string> hashes, ConcurrentDictionary<string, IndicatorOfCompromise> iocs)
        {
            const string feedName = "abuse.ch-hashes";
            var authKey = _context.Config.AbuseChAuthKey;

            if (string.IsNullOrEmpty(authKey))
            {
                _context.Log(LogLevel.Info, ModuleName, "abuse.ch feeds require Auth-Key (free at auth.abuse.ch). Skipping.");
                RecordFeedHealth(feedName, false, 0, "No Auth-Key configured");
                return;
            }

            var url = $"https://mb-api.abuse.ch/v2/files/exports/{authKey}/recent.csv";

            try
            {
                var csv = await _http.GetStringAsync(url);
                var lines = csv.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                int parsed = 0;

                foreach (var line in lines)
                {
                    if (line.StartsWith('#') || line.StartsWith("first_seen"))
                        continue;

                    var cols = line.Split(',');
                    if (cols.Length < 3) continue;

                    // CSV columns: first_seen_utc, md5_hash, sha256_hash, ...
                    var sha256 = cols.Length > 2 ? cols[2].Trim().Trim('"') : null;
                    if (string.IsNullOrEmpty(sha256) || sha256.Length != 64)
                        continue;

                    lock (hashes) hashes.Add(sha256);
                    iocs[BuildIocKey("hash", sha256)] = new IndicatorOfCompromise
                    {
                        Type = "hash",
                        Value = sha256,
                        Source = feedName,
                        LastSeen = DateTime.UtcNow
                    };
                    parsed++;
                }

                RecordFeedHealth(feedName, true, parsed);
            }
            catch (Exception ex)
            {
                _context.Log(LogLevel.Warning, ModuleName, $"Failed to fetch {feedName}: {ex.Message}");
                RecordFeedHealth(feedName, false, 0, ex.Message);
            }
        }

        // --- Feed: ThreatFox IOC API ---

        private async Task FetchThreatFox(
            HashSet<string> extensions,
            HashSet<string> ransomNotes,
            HashSet<string> processNames,
            HashSet<string> hashes,
            ConcurrentDictionary<string, IndicatorOfCompromise> iocs)
        {
            const string feedName = "threatfox";
            const string url = "https://threatfox-api.abuse.ch/api/v1/";
            var authKey = _context.Config.AbuseChAuthKey;

            if (string.IsNullOrEmpty(authKey))
            {
                RecordFeedHealth(feedName, false, 0, "No Auth-Key configured");
                return;
            }

            try
            {
                var request = new HttpRequestMessage(HttpMethod.Post, url);
                request.Headers.Add("Auth-Key", authKey);
                request.Content = new StringContent(
                    JsonSerializer.Serialize(new { query = "get_iocs", days = 7 }),
                    System.Text.Encoding.UTF8, "application/json");

                var response = await _http.SendAsync(request);
                response.EnsureSuccessStatusCode();

                var json = await response.Content.ReadAsStringAsync();
                var result = JsonSerializer.Deserialize<ThreatFoxResponse>(json);

                if (result?.QueryStatus != "ok" || result.Data == null)
                {
                    _context.Log(LogLevel.Warning, ModuleName, $"ThreatFox returned status: {result?.QueryStatus}");
                    RecordFeedHealth(feedName, false, 0, $"API status: {result?.QueryStatus}");
                    return;
                }

                int parsed = 0;
                foreach (var ioc in result.Data)
                {
                    if (string.IsNullOrEmpty(ioc.IocType) || string.IsNullOrEmpty(ioc.IocValue))
                        continue;

                    // Filter for ransomware-related IOCs
                    var malwareType = ioc.MalwarePrintable?.ToLowerInvariant() ?? "";
                    var threatType = ioc.ThreatType?.ToLowerInvariant() ?? "";
                    bool isRansomware = malwareType.Contains("ransom") || threatType.Contains("ransom")
                        || threatType.Contains("crypto") || malwareType.Contains("locker");

                    if (!isRansomware) continue;

                    var iocType = ioc.IocType.ToLowerInvariant();
                    var iocValue = ioc.IocValue.Trim();

                    if (iocType.Contains("sha256") || iocType.Contains("hash"))
                    {
                        // Extract hash from potential "sha256:value" format
                        var hash = iocValue.Contains(':') ? iocValue.Split(':').Last().Trim() : iocValue;
                        if (hash.Length == 64)
                        {
                            lock (hashes) hashes.Add(hash);
                            iocs[BuildIocKey("hash", hash)] = new IndicatorOfCompromise
                            {
                                Type = "hash", Value = hash, Source = feedName, LastSeen = DateTime.UtcNow
                            };
                        }
                    }
                    else if (iocType.Contains("payload") && iocValue.Contains('.'))
                    {
                        // Payload filenames may reveal process names
                        var filename = Path.GetFileNameWithoutExtension(iocValue);
                        if (!string.IsNullOrEmpty(filename))
                        {
                            lock (processNames) processNames.Add(filename);
                        }
                    }

                    parsed++;
                }

                RecordFeedHealth(feedName, true, parsed);
            }
            catch (Exception ex)
            {
                _context.Log(LogLevel.Warning, ModuleName, $"Failed to fetch {feedName}: {ex.Message}");
                RecordFeedHealth(feedName, false, 0, ex.Message);
            }
        }

        // --- Feed: Central Dashboard (Paul's curated list) ---

        private async Task FetchDashboardFeed(
            HashSet<string> extensions,
            HashSet<string> ransomNotes,
            HashSet<string> processNames,
            HashSet<string> hashes,
            ConcurrentDictionary<string, IndicatorOfCompromise> iocs)
        {
            const string feedName = "dashboard";
            var feedUrl = _context.Config.GetValue("threatFeedUrl");

            if (string.IsNullOrWhiteSpace(feedUrl))
            {
                RecordFeedHealth(feedName, false, 0, "Not configured (set threatFeedUrl in config)");
                return;
            }

            try
            {
                var request = new HttpRequestMessage(HttpMethod.Get, feedUrl);
                var apiToken = _context.Config.DashboardApiToken;
                if (!string.IsNullOrEmpty(apiToken))
                    request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", apiToken);

                var response = await _http.SendAsync(request);
                response.EnsureSuccessStatusCode();

                var json = await response.Content.ReadAsStringAsync();
                var feed = JsonSerializer.Deserialize<DashboardFeed>(json);
                if (feed == null)
                {
                    RecordFeedHealth(feedName, false, 0, "Empty or invalid response");
                    return;
                }

                int parsed = 0;
                MergeList(feed.Extensions, extensions, "extension", feedName, iocs, ref parsed);
                MergeList(feed.RansomNotes, ransomNotes, "ransomnote", feedName, iocs, ref parsed);
                MergeList(feed.ProcessNames, processNames, "process", feedName, iocs, ref parsed);
                MergeList(feed.FileHashes, hashes, "hash", feedName, iocs, ref parsed);

                RecordFeedHealth(feedName, true, parsed);
            }
            catch (Exception ex)
            {
                _context.Log(LogLevel.Warning, ModuleName, $"Failed to fetch {feedName}: {ex.Message}");
                RecordFeedHealth(feedName, false, 0, ex.Message);
            }
        }

        // --- Feed: Local Custom Indicators ---

        private void LoadCustomIndicators(
            HashSet<string> extensions,
            HashSet<string> ransomNotes,
            HashSet<string> processNames,
            HashSet<string> hashes,
            ConcurrentDictionary<string, IndicatorOfCompromise> iocs)
        {
            const string feedName = "custom";
            try
            {
                if (!File.Exists(CustomIndicatorsPath))
                {
                    RecordFeedHealth(feedName, true, 0);
                    return;
                }

                var json = File.ReadAllText(CustomIndicatorsPath);
                var custom = JsonSerializer.Deserialize<CustomIndicatorsFile>(json);
                if (custom == null)
                {
                    RecordFeedHealth(feedName, true, 0);
                    return;
                }

                int parsed = 0;
                MergeList(custom.Extensions, extensions, "extension", feedName, iocs, ref parsed);
                MergeList(custom.RansomNotes, ransomNotes, "ransomnote", feedName, iocs, ref parsed);
                MergeList(custom.ProcessNames, processNames, "process", feedName, iocs, ref parsed);
                MergeList(custom.FileHashes, hashes, "hash", feedName, iocs, ref parsed);

                RecordFeedHealth(feedName, true, parsed);
            }
            catch (Exception ex)
            {
                _context.Log(LogLevel.Warning, ModuleName, $"Failed to load custom indicators: {ex.Message}");
                RecordFeedHealth(feedName, false, 0, ex.Message);
            }
        }

        // --- Persistence ---

        private void PersistData()
        {
            try
            {
                Directory.CreateDirectory(DataDir);

                PersistedThreatIntel data;
                lock (_lock)
                {
                    data = new PersistedThreatIntel
                    {
                        Extensions = _knownExtensions.ToList(),
                        RansomNotes = _knownRansomNotes.ToList(),
                        ProcessNames = _knownProcessNames.ToList(),
                        FileHashes = _knownFileHashes.ToList(),
                        Iocs = _iocs.Values.ToList(),
                        LastUpdate = _lastUpdate
                    };
                }

                var json = JsonSerializer.Serialize(data, SerializerOptions);
                var tempPath = PersistPath + ".tmp";
                File.WriteAllText(tempPath, json);
                File.Move(tempPath, PersistPath, overwrite: true);
            }
            catch (Exception ex)
            {
                _context.Log(LogLevel.Error, ModuleName, $"Failed to persist threat intel: {ex.Message}");
            }
        }

        private void LoadPersistedData()
        {
            try
            {
                if (!File.Exists(PersistPath)) return;

                var json = File.ReadAllText(PersistPath);
                var data = JsonSerializer.Deserialize<PersistedThreatIntel>(json);
                if (data == null) return;

                lock (_lock)
                {
                    if (data.Extensions?.Count > 0)
                        foreach (var e in data.Extensions) _knownExtensions.Add(e);
                    if (data.RansomNotes?.Count > 0)
                        foreach (var n in data.RansomNotes) _knownRansomNotes.Add(n);
                    if (data.ProcessNames?.Count > 0)
                        foreach (var p in data.ProcessNames) _knownProcessNames.Add(p);
                    if (data.FileHashes?.Count > 0)
                        foreach (var h in data.FileHashes) _knownFileHashes.Add(h);

                    if (data.Iocs != null)
                    {
                        foreach (var ioc in data.Iocs)
                            _iocs[BuildIocKey(ioc.Type, ioc.Value)] = ioc;
                    }

                    _lastUpdate = data.LastUpdate;
                }

                var age = DateTime.UtcNow - _lastUpdate;
                var ageStr = age.TotalHours < 24 ? $"{age.TotalHours:F0}h" : $"{age.TotalDays:F0}d";
                _context.Log(LogLevel.Info, ModuleName,
                    $"Loaded offline IOC cache ({ageStr} old, {_iocs.Count} IOCs, {_knownFileHashes.Count} hashes)");
            }
            catch (Exception ex)
            {
                _context.Log(LogLevel.Warning, ModuleName, $"Failed to load persisted data: {ex.Message}");
            }
        }

        private void SaveCustomIndicator(string type, string value)
        {
            try
            {
                Directory.CreateDirectory(DataDir);

                CustomIndicatorsFile custom;
                if (File.Exists(CustomIndicatorsPath))
                {
                    var existing = File.ReadAllText(CustomIndicatorsPath);
                    custom = JsonSerializer.Deserialize<CustomIndicatorsFile>(existing) ?? new();
                }
                else
                {
                    custom = new CustomIndicatorsFile();
                }

                var targetList = type switch
                {
                    "extension" => custom.Extensions ??= new(),
                    "ransomnote" => custom.RansomNotes ??= new(),
                    "process" => custom.ProcessNames ??= new(),
                    "hash" => custom.FileHashes ??= new(),
                    _ => null
                };

                if (targetList != null && !targetList.Contains(value))
                {
                    targetList.Add(value);
                    File.WriteAllText(CustomIndicatorsPath, JsonSerializer.Serialize(custom, SerializerOptions));
                }
            }
            catch (Exception ex)
            {
                _context.Log(LogLevel.Warning, ModuleName, $"Failed to save custom indicator: {ex.Message}");
            }
        }

        // --- Helpers ---

        private static void MergeList(
            List<string>? source,
            HashSet<string> target,
            string iocType,
            string feedName,
            ConcurrentDictionary<string, IndicatorOfCompromise> iocs,
            ref int count)
        {
            if (source == null) return;
            foreach (var item in source)
            {
                if (string.IsNullOrWhiteSpace(item)) continue;
                lock (target) target.Add(item);
                iocs[BuildIocKey(iocType, item)] = new IndicatorOfCompromise
                {
                    Type = iocType, Value = item, Source = feedName, LastSeen = DateTime.UtcNow
                };
                count++;
            }
        }

        private void RecordFeedHealth(string feedName, bool success, int count, string? error = null)
        {
            lock (_feedHealth)
            {
                _feedHealth[feedName] = new FeedHealth
                {
                    Name = feedName,
                    LastAttempt = DateTime.UtcNow,
                    LastSuccess = success ? DateTime.UtcNow : (_feedHealth.TryGetValue(feedName, out var prev) ? prev.LastSuccess : null),
                    IsHealthy = success,
                    IndicatorCount = count,
                    LastError = error
                };
            }
        }

        private static string BuildIocKey(string type, string value) => $"{type}:{value}";

        private static readonly JsonSerializerOptions SerializerOptions = new()
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        // --- Base Indicators (offline fallback, matches RansomwareModule static lists) ---

        private static readonly HashSet<string> BaseExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".encrypted", ".locked", ".crypto", ".crypt", ".enc", ".locky",
            ".cerber", ".zepto", ".thor", ".aesir", ".zzzzz", ".micro",
            ".vvv", ".ccc", ".abc", ".ecc", ".ezz", ".exx",
            ".wncry", ".wcry", ".wnry", ".wncrypt",
            ".WANNA_DECRYPT", ".REVENGE", ".GANDCRAB",
            ".CONTI", ".HIVE", ".LOCKBIT", ".BLACKCAT",
            ".revil", ".sodinokibi", ".ryuk", ".maze", ".clop",
            ".ransomware", ".pays", ".ransom"
        };

        private static readonly HashSet<string> BaseRansomNotes = new(StringComparer.OrdinalIgnoreCase)
        {
            "README_TO_DECRYPT.txt", "HOW_TO_DECRYPT.txt", "DECRYPT_INSTRUCTIONS.txt",
            "YOUR_FILES_ARE_ENCRYPTED.txt", "RECOVERY_INSTRUCTIONS.txt",
            "_readme.txt", "HELP_RECOVER.txt", "!!! READ ME !!!.txt",
            "RESTORE_FILES.txt", "ATTENTION!!!.txt", "warning.html",
            "HOW-TO-DECRYPT-FILES.txt", "HELP_DECRYPT.html",
            "ransom_note.txt", "!_HOW_RECOVERY.txt", "DECRYPT_YOUR_FILES.html"
        };

        private static readonly HashSet<string> BaseProcessNames = new(StringComparer.OrdinalIgnoreCase)
        {
            "wannacry", "wcry", "wncrypt", "tasksche",
            "cerber", "locky", "cryptolocker", "teslacrypt",
            "gandcrab", "sodinokibi", "ryuk", "conti",
            "lockbit", "blackcat", "alphv", "hive",
            "maze", "clop", "revil", "darkside",
            "babuk", "avaddon", "ragnar_locker"
        };

        // --- DTOs ---

        private class ThreatFoxResponse
        {
            [JsonPropertyName("query_status")]
            public string? QueryStatus { get; set; }

            [JsonPropertyName("data")]
            public List<ThreatFoxIoc>? Data { get; set; }
        }

        private class ThreatFoxIoc
        {
            [JsonPropertyName("ioc_type")]
            public string? IocType { get; set; }

            [JsonPropertyName("ioc_value")]
            public string? IocValue { get; set; }

            [JsonPropertyName("threat_type")]
            public string? ThreatType { get; set; }

            [JsonPropertyName("malware_printable")]
            public string? MalwarePrintable { get; set; }
        }

        private class DashboardFeed
        {
            [JsonPropertyName("extensions")]
            public List<string>? Extensions { get; set; }

            [JsonPropertyName("ransomNotes")]
            public List<string>? RansomNotes { get; set; }

            [JsonPropertyName("processNames")]
            public List<string>? ProcessNames { get; set; }

            [JsonPropertyName("fileHashes")]
            public List<string>? FileHashes { get; set; }
        }

        private class CustomIndicatorsFile
        {
            [JsonPropertyName("extensions")]
            public List<string>? Extensions { get; set; }

            [JsonPropertyName("ransomNotes")]
            public List<string>? RansomNotes { get; set; }

            [JsonPropertyName("processNames")]
            public List<string>? ProcessNames { get; set; }

            [JsonPropertyName("fileHashes")]
            public List<string>? FileHashes { get; set; }
        }

        private class PersistedThreatIntel
        {
            [JsonPropertyName("extensions")]
            public List<string>? Extensions { get; set; }

            [JsonPropertyName("ransomNotes")]
            public List<string>? RansomNotes { get; set; }

            [JsonPropertyName("processNames")]
            public List<string>? ProcessNames { get; set; }

            [JsonPropertyName("fileHashes")]
            public List<string>? FileHashes { get; set; }

            [JsonPropertyName("iocs")]
            public List<IndicatorOfCompromise>? Iocs { get; set; }

            [JsonPropertyName("lastUpdate")]
            public DateTime LastUpdate { get; set; }
        }
    }

    // --- Public Models ---

    public class IndicatorOfCompromise
    {
        [JsonPropertyName("type")]
        public string Type { get; set; } = "";

        [JsonPropertyName("value")]
        public string Value { get; set; } = "";

        [JsonPropertyName("source")]
        public string Source { get; set; } = "";

        [JsonPropertyName("lastSeen")]
        public DateTime LastSeen { get; set; }
    }

    public class ThreatIntelStatus
    {
        public int ExtensionCount { get; set; }
        public int RansomNoteCount { get; set; }
        public int ProcessNameCount { get; set; }
        public int FileHashCount { get; set; }
        public int IocCount { get; set; }
        public DateTime LastUpdate { get; set; }
        public Dictionary<string, FeedHealth> FeedHealth { get; set; } = new();
    }

    public class FeedHealth
    {
        public string Name { get; set; } = "";
        public DateTime LastAttempt { get; set; }
        public DateTime? LastSuccess { get; set; }
        public bool IsHealthy { get; set; }
        public int IndicatorCount { get; set; }
        public string? LastError { get; set; }
    }
}
