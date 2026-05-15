using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;
using PCPlus.Core.Interfaces;
using PCPlus.Core.Models;

namespace PCPlus.Service.Modules.Phishing
{
    public class PhishingModule : IModule
    {
        public string Id => "phishing";
        public string Name => "Phishing Protection";
        public string Version => "1.0.0";
        public LicenseTier RequiredTier => LicenseTier.Standard;
        public bool IsRunning { get; private set; }

        private IModuleContext _context = null!;
        private Timer? _dnsUpdateTimer;
        private Timer? _hostsFileWatcher;
        private readonly object _lock = new();
        private readonly HashSet<string> _blockedDomains = new(StringComparer.OrdinalIgnoreCase);
        private readonly List<PhishingEvent> _events = new();
        private readonly Dictionary<string, int> _blockCounts = new(StringComparer.OrdinalIgnoreCase);
        private DateTime _lastBlocklistUpdate = DateTime.MinValue;
        private int _totalBlocked;
        private bool _dnsProtectionActive;

        private static readonly string HostsFilePath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "drivers", "etc", "hosts");

        private static readonly string BlocklistDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "PCPlusEndpoint", "phishing");

        private static readonly string BlocklistFile = Path.Combine(BlocklistDir, "blocklist.txt");
        private static readonly string CustomBlockFile = Path.Combine(BlocklistDir, "custom-blocks.txt");
        private static readonly string WhitelistFile = Path.Combine(BlocklistDir, "whitelist.txt");
        private static readonly string EventLogFile = Path.Combine(BlocklistDir, "phishing-events.json");

        private const string HOSTS_MARKER_START = "# === PCPlus Phishing Protection START ===";
        private const string HOSTS_MARKER_END = "# === PCPlus Phishing Protection END ===";

        private static readonly string[] BlocklistUrls = new[]
        {
            "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
            "https://phishing.army/download/phishing_army_blocklist.txt",
        };

        private static readonly Regex DomainRegex = new(
            @"^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.[a-zA-Z0-9-]{1,63})*\.[a-zA-Z]{2,}$",
            RegexOptions.Compiled);

        // Known phishing TLD patterns
        private static readonly HashSet<string> SuspiciousTlds = new(StringComparer.OrdinalIgnoreCase)
        {
            ".xyz", ".top", ".club", ".work", ".buzz", ".surf",
            ".tk", ".ml", ".ga", ".cf", ".gq",
            ".icu", ".cam", ".rest", ".monster"
        };

        // Brand impersonation patterns
        private static readonly (string brand, string[] patterns)[] BrandPatterns = new[]
        {
            ("Microsoft", new[] { "microsoft-login", "ms-office-", "outlook-verify", "microsoft365-", "sharepoint-auth" }),
            ("Google", new[] { "google-verify", "gmail-login", "drive-share-", "docs-google-" }),
            ("Apple", new[] { "apple-verify", "icloud-login", "appleid-", "apple-support-" }),
            ("Amazon", new[] { "amazon-verify", "aws-login", "prime-renew" }),
            ("PayPal", new[] { "paypal-verify", "paypal-secure", "paypal-login" }),
            ("Banking", new[] { "secure-banking", "bank-verify", "account-suspend", "update-billing" }),
        };

        // URL shorteners commonly abused
        private static readonly HashSet<string> UrlShorteners = new(StringComparer.OrdinalIgnoreCase)
        {
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
            "is.gd", "buff.ly", "adf.ly", "bit.do", "lnkd.in"
        };

        public Task InitializeAsync(IModuleContext context)
        {
            _context = context;
            Directory.CreateDirectory(BlocklistDir);
            LoadBlocklist();
            LoadEvents();
            return Task.CompletedTask;
        }

        public async Task StartAsync(CancellationToken cancellationToken)
        {
            IsRunning = true;
            _context.Log(LogLevel.Info, Id, $"Phishing Protection starting. {_blockedDomains.Count} domains in blocklist.");

            // Initial blocklist update
            await UpdateBlocklistAsync();

            // Apply DNS-level blocking via hosts file
            ApplyHostsFileBlocking();
            _dnsProtectionActive = true;

            // Update blocklist every 6 hours
            _dnsUpdateTimer = new Timer(async _ =>
            {
                try { await UpdateBlocklistAsync(); ApplyHostsFileBlocking(); }
                catch (Exception ex) { _context.Log(LogLevel.Error, Id, $"Blocklist update failed: {ex.Message}"); }
            }, null, TimeSpan.FromHours(6), TimeSpan.FromHours(6));

            // Monitor hosts file integrity every 60 seconds
            _hostsFileWatcher = new Timer(_ =>
            {
                try { VerifyHostsFileIntegrity(); }
                catch (Exception ex) { _context.Log(LogLevel.Error, Id, $"Hosts file check failed: {ex.Message}"); }
            }, null, TimeSpan.FromSeconds(60), TimeSpan.FromSeconds(60));

            _context.Log(LogLevel.Info, Id, "Phishing Protection active.");
        }

        public Task StopAsync()
        {
            IsRunning = false;
            _dnsUpdateTimer?.Dispose();
            _hostsFileWatcher?.Dispose();
            RemoveHostsFileBlocking();
            _dnsProtectionActive = false;
            SaveEvents();
            _context.Log(LogLevel.Info, Id, "Phishing Protection stopped. Hosts file cleaned.");
            return Task.CompletedTask;
        }

        public Task<ModuleResponse> HandleCommandAsync(ModuleCommand command)
        {
            switch (command.Action.ToLowerInvariant())
            {
                case "getstatus":
                    return Task.FromResult(ModuleResponse.Ok("Phishing protection status", new Dictionary<string, object>
                    {
                        ["dnsProtectionActive"] = _dnsProtectionActive,
                        ["blockedDomainCount"] = _blockedDomains.Count,
                        ["totalBlocked"] = _totalBlocked,
                        ["lastUpdate"] = _lastBlocklistUpdate.ToString("o"),
                        ["recentEvents"] = _events.TakeLast(20).Reverse().ToList()
                    }));

                case "checkdomain":
                    if (command.Parameters.TryGetValue("domain", out var domain))
                    {
                        var result = AnalyzeDomain(domain);
                        return Task.FromResult(ModuleResponse.Ok("Domain analysis", new Dictionary<string, object>
                        {
                            ["domain"] = domain,
                            ["blocked"] = result.IsBlocked,
                            ["riskLevel"] = result.RiskLevel.ToString(),
                            ["reasons"] = result.Reasons
                        }));
                    }
                    return Task.FromResult(ModuleResponse.Fail("Missing 'domain' parameter"));

                case "checkurl":
                    if (command.Parameters.TryGetValue("url", out var url))
                    {
                        var result = AnalyzeUrl(url);
                        return Task.FromResult(ModuleResponse.Ok("URL analysis", new Dictionary<string, object>
                        {
                            ["url"] = url,
                            ["blocked"] = result.IsBlocked,
                            ["riskLevel"] = result.RiskLevel.ToString(),
                            ["reasons"] = result.Reasons
                        }));
                    }
                    return Task.FromResult(ModuleResponse.Fail("Missing 'url' parameter"));

                case "blockdomain":
                    if (command.Parameters.TryGetValue("domain", out var blockDomain))
                    {
                        AddCustomBlock(blockDomain);
                        ApplyHostsFileBlocking();
                        return Task.FromResult(ModuleResponse.Ok($"Domain '{blockDomain}' added to blocklist"));
                    }
                    return Task.FromResult(ModuleResponse.Fail("Missing 'domain' parameter"));

                case "unblockdomain":
                    if (command.Parameters.TryGetValue("domain", out var unblockDomain))
                    {
                        AddWhitelist(unblockDomain);
                        ApplyHostsFileBlocking();
                        return Task.FromResult(ModuleResponse.Ok($"Domain '{unblockDomain}' whitelisted"));
                    }
                    return Task.FromResult(ModuleResponse.Fail("Missing 'domain' parameter"));

                case "updateblocklist":
                    _ = Task.Run(async () =>
                    {
                        await UpdateBlocklistAsync();
                        ApplyHostsFileBlocking();
                    });
                    return Task.FromResult(ModuleResponse.Ok("Blocklist update started"));

                case "getevents":
                    int count = 50;
                    if (command.Parameters.TryGetValue("count", out var countStr))
                        int.TryParse(countStr, out count);
                    return Task.FromResult(ModuleResponse.Ok("Phishing events", new Dictionary<string, object>
                    {
                        ["events"] = _events.TakeLast(count).Reverse().ToList(),
                        ["totalEvents"] = _events.Count
                    }));

                case "getstats":
                    return Task.FromResult(ModuleResponse.Ok("Phishing stats", new Dictionary<string, object>
                    {
                        ["totalBlocked"] = _totalBlocked,
                        ["blockedDomains"] = _blockedDomains.Count,
                        ["topBlocked"] = _blockCounts.OrderByDescending(kv => kv.Value).Take(10)
                            .ToDictionary(kv => kv.Key, kv => (object)kv.Value),
                        ["lastUpdate"] = _lastBlocklistUpdate.ToString("o"),
                        ["recentEvents24h"] = _events.Count(e => e.Timestamp > DateTime.UtcNow.AddHours(-24))
                    }));

                default:
                    return Task.FromResult(ModuleResponse.Fail($"Unknown action: {command.Action}"));
            }
        }

        public ModuleStatus GetStatus()
        {
            return new ModuleStatus
            {
                ModuleId = Id,
                ModuleName = Name,
                IsRunning = IsRunning,
                RequiredTier = RequiredTier,
                StatusText = _dnsProtectionActive
                    ? $"Active - {_blockedDomains.Count:N0} domains blocked, {_totalBlocked} hits"
                    : "Inactive",
                LastActivity = _events.LastOrDefault()?.Timestamp ?? DateTime.MinValue,
                Metrics = new Dictionary<string, object>
                {
                    ["blockedDomainCount"] = _blockedDomains.Count,
                    ["totalBlocked"] = _totalBlocked,
                    ["dnsProtectionActive"] = _dnsProtectionActive,
                    ["lastBlocklistUpdate"] = _lastBlocklistUpdate.ToString("o"),
                    ["eventsLast24h"] = _events.Count(e => e.Timestamp > DateTime.UtcNow.AddHours(-24))
                }
            };
        }

        #region Domain Analysis

        private DomainAnalysis AnalyzeDomain(string domain)
        {
            domain = domain.Trim().ToLowerInvariant().TrimEnd('.');
            var reasons = new List<string>();
            int riskScore = 0;

            if (_blockedDomains.Contains(domain))
            {
                reasons.Add("Domain is on phishing blocklist");
                riskScore += 100;
            }

            if (SuspiciousTlds.Any(tld => domain.EndsWith(tld)))
            {
                reasons.Add($"Uses suspicious TLD");
                riskScore += 20;
            }

            foreach (var (brand, patterns) in BrandPatterns)
            {
                if (patterns.Any(p => domain.Contains(p, StringComparison.OrdinalIgnoreCase)))
                {
                    reasons.Add($"Possible {brand} impersonation");
                    riskScore += 60;
                    break;
                }
            }

            if (UrlShorteners.Contains(domain))
            {
                reasons.Add("URL shortener (commonly used for phishing)");
                riskScore += 15;
            }

            // Homograph detection (mixed scripts)
            if (ContainsMixedScripts(domain))
            {
                reasons.Add("Contains mixed character scripts (possible homograph attack)");
                riskScore += 50;
            }

            // Excessive subdomains
            if (domain.Count(c => c == '.') > 4)
            {
                reasons.Add("Excessive subdomains (common phishing pattern)");
                riskScore += 15;
            }

            // Long domain name
            var mainDomain = domain.Split('.').FirstOrDefault() ?? "";
            if (mainDomain.Length > 30)
            {
                reasons.Add("Unusually long domain name");
                riskScore += 10;
            }

            var level = riskScore switch
            {
                >= 80 => RiskLevel.Critical,
                >= 50 => RiskLevel.High,
                >= 20 => RiskLevel.Medium,
                > 0 => RiskLevel.Low,
                _ => RiskLevel.Safe
            };

            return new DomainAnalysis
            {
                Domain = domain,
                IsBlocked = _blockedDomains.Contains(domain),
                RiskLevel = level,
                RiskScore = riskScore,
                Reasons = reasons
            };
        }

        private DomainAnalysis AnalyzeUrl(string url)
        {
            try
            {
                if (!url.StartsWith("http"))
                    url = "https://" + url;
                var uri = new Uri(url);
                var analysis = AnalyzeDomain(uri.Host);

                // Additional URL-level checks
                if (uri.AbsolutePath.Contains("login", StringComparison.OrdinalIgnoreCase) ||
                    uri.AbsolutePath.Contains("signin", StringComparison.OrdinalIgnoreCase) ||
                    uri.AbsolutePath.Contains("verify", StringComparison.OrdinalIgnoreCase))
                {
                    if (analysis.RiskScore > 0)
                    {
                        analysis.Reasons.Add("URL contains authentication-related path on suspicious domain");
                        analysis.RiskScore += 20;
                    }
                }

                if (uri.Query.Contains("redirect", StringComparison.OrdinalIgnoreCase) ||
                    uri.Query.Contains("url=", StringComparison.OrdinalIgnoreCase))
                {
                    analysis.Reasons.Add("URL contains redirect parameter");
                    analysis.RiskScore += 10;
                }

                // IP address instead of domain
                if (IPAddress.TryParse(uri.Host, out _))
                {
                    analysis.Reasons.Add("Uses IP address instead of domain name");
                    analysis.RiskScore += 30;
                }

                analysis.RiskLevel = analysis.RiskScore switch
                {
                    >= 80 => RiskLevel.Critical,
                    >= 50 => RiskLevel.High,
                    >= 20 => RiskLevel.Medium,
                    > 0 => RiskLevel.Low,
                    _ => RiskLevel.Safe
                };

                return analysis;
            }
            catch
            {
                return new DomainAnalysis { Domain = url, RiskLevel = RiskLevel.Low, Reasons = new List<string> { "Could not parse URL" } };
            }
        }

        private static bool ContainsMixedScripts(string domain)
        {
            bool hasLatin = false, hasNonLatin = false;
            foreach (char c in domain)
            {
                if (c == '.' || c == '-') continue;
                if (c >= 'a' && c <= 'z' || c >= '0' && c <= '9') hasLatin = true;
                else if (c > 127) hasNonLatin = true;
            }
            return hasLatin && hasNonLatin;
        }

        #endregion

        #region Blocklist Management

        private async Task UpdateBlocklistAsync()
        {
            var newDomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };

            foreach (var url in BlocklistUrls)
            {
                try
                {
                    var content = await client.GetStringAsync(url);
                    foreach (var line in content.Split('\n', StringSplitOptions.RemoveEmptyEntries))
                    {
                        var trimmed = line.Trim();
                        if (trimmed.StartsWith('#') || string.IsNullOrEmpty(trimmed)) continue;

                        // Steven Black format: "0.0.0.0 domain.com"
                        var parts = trimmed.Split(' ', '\t');
                        string domain;
                        if (parts.Length >= 2 && (parts[0] == "0.0.0.0" || parts[0] == "127.0.0.1"))
                            domain = parts[1].Trim().ToLowerInvariant();
                        else if (parts.Length == 1 && DomainRegex.IsMatch(parts[0]))
                            domain = parts[0].Trim().ToLowerInvariant();
                        else
                            continue;

                        if (domain != "localhost" && domain.Contains('.'))
                            newDomains.Add(domain);
                    }
                    _context.Log(LogLevel.Info, Id, $"Loaded blocklist from {url}: {newDomains.Count} domains total");
                }
                catch (Exception ex)
                {
                    _context.Log(LogLevel.Warning, Id, $"Failed to fetch {url}: {ex.Message}");
                }
            }

            // Load custom blocks
            if (File.Exists(CustomBlockFile))
            {
                foreach (var line in await File.ReadAllLinesAsync(CustomBlockFile))
                {
                    var d = line.Trim().ToLowerInvariant();
                    if (!string.IsNullOrEmpty(d) && !d.StartsWith('#'))
                        newDomains.Add(d);
                }
            }

            // Remove whitelisted
            var whitelist = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (File.Exists(WhitelistFile))
            {
                foreach (var line in await File.ReadAllLinesAsync(WhitelistFile))
                {
                    var d = line.Trim().ToLowerInvariant();
                    if (!string.IsNullOrEmpty(d) && !d.StartsWith('#'))
                        whitelist.Add(d);
                }
            }
            newDomains.ExceptWith(whitelist);

            if (newDomains.Count > 0)
            {
                lock (_lock)
                {
                    _blockedDomains.Clear();
                    foreach (var d in newDomains) _blockedDomains.Add(d);
                }
                await File.WriteAllLinesAsync(BlocklistFile, newDomains.OrderBy(d => d));
                _lastBlocklistUpdate = DateTime.UtcNow;
                _context.Log(LogLevel.Info, Id, $"Blocklist updated: {_blockedDomains.Count:N0} domains");
            }
        }

        private void LoadBlocklist()
        {
            if (!File.Exists(BlocklistFile)) return;
            try
            {
                foreach (var line in File.ReadLines(BlocklistFile))
                {
                    var d = line.Trim();
                    if (!string.IsNullOrEmpty(d)) _blockedDomains.Add(d);
                }
            }
            catch { }
        }

        private void AddCustomBlock(string domain)
        {
            domain = domain.Trim().ToLowerInvariant();
            lock (_lock) { _blockedDomains.Add(domain); }
            try { File.AppendAllText(CustomBlockFile, domain + Environment.NewLine); } catch { }
            RecordEvent("custom_block", domain, "Manually blocked by admin");
        }

        private void AddWhitelist(string domain)
        {
            domain = domain.Trim().ToLowerInvariant();
            lock (_lock) { _blockedDomains.Remove(domain); }
            try { File.AppendAllText(WhitelistFile, domain + Environment.NewLine); } catch { }
            RecordEvent("whitelist", domain, "Manually whitelisted by admin");
        }

        #endregion

        #region DNS Blocking (Hosts File)

        private void ApplyHostsFileBlocking()
        {
            try
            {
                var existingLines = File.Exists(HostsFilePath)
                    ? File.ReadAllLines(HostsFilePath).ToList()
                    : new List<string>();

                // Remove our existing section
                int startIdx = existingLines.FindIndex(l => l.Contains(HOSTS_MARKER_START));
                int endIdx = existingLines.FindIndex(l => l.Contains(HOSTS_MARKER_END));
                if (startIdx >= 0 && endIdx >= startIdx)
                    existingLines.RemoveRange(startIdx, endIdx - startIdx + 1);

                // Add our section
                var ourLines = new List<string> { HOSTS_MARKER_START };

                // Limit to top domains to avoid huge hosts file
                // Use curated phishing list (phishing.army is more targeted than Steven Black's full list)
                HashSet<string> phishingOnly;
                lock (_lock)
                {
                    phishingOnly = new HashSet<string>(_blockedDomains.Take(50000), StringComparer.OrdinalIgnoreCase);
                }

                foreach (var domain in phishingOnly.OrderBy(d => d))
                {
                    ourLines.Add($"0.0.0.0 {domain}");
                }
                ourLines.Add(HOSTS_MARKER_END);

                existingLines.AddRange(ourLines);
                File.WriteAllLines(HostsFilePath, existingLines);

                _context.Log(LogLevel.Info, Id, $"Hosts file updated: {phishingOnly.Count:N0} phishing domains blocked");
            }
            catch (Exception ex)
            {
                _context.Log(LogLevel.Error, Id, $"Failed to update hosts file: {ex.Message}");
            }
        }

        private void RemoveHostsFileBlocking()
        {
            try
            {
                if (!File.Exists(HostsFilePath)) return;
                var lines = File.ReadAllLines(HostsFilePath).ToList();
                int startIdx = lines.FindIndex(l => l.Contains(HOSTS_MARKER_START));
                int endIdx = lines.FindIndex(l => l.Contains(HOSTS_MARKER_END));
                if (startIdx >= 0 && endIdx >= startIdx)
                {
                    lines.RemoveRange(startIdx, endIdx - startIdx + 1);
                    File.WriteAllLines(HostsFilePath, lines);
                }
            }
            catch (Exception ex)
            {
                _context.Log(LogLevel.Error, Id, $"Failed to clean hosts file: {ex.Message}");
            }
        }

        private void VerifyHostsFileIntegrity()
        {
            if (!File.Exists(HostsFilePath)) return;
            var content = File.ReadAllText(HostsFilePath);

            if (_dnsProtectionActive && !content.Contains(HOSTS_MARKER_START))
            {
                _context.Log(LogLevel.Warning, Id, "Hosts file protection was removed externally. Reapplying.");
                _context.RaiseAlert(new Alert
                {
                    ModuleId = Id,
                    Title = "Phishing Protection Tampered",
                    Message = "The hosts file phishing protection block was removed by an external process. It has been reapplied.",
                    Severity = AlertSeverity.Warning,
                    Category = "phishing"
                });
                ApplyHostsFileBlocking();
                RecordEvent("tamper_detected", "hosts_file", "Hosts file protection was removed externally and reapplied");
            }
        }

        #endregion

        #region Event Logging

        private void RecordEvent(string eventType, string domain, string detail)
        {
            var evt = new PhishingEvent
            {
                Type = eventType,
                Domain = domain,
                Detail = detail,
                Timestamp = DateTime.UtcNow
            };

            lock (_lock)
            {
                _events.Add(evt);
                if (_events.Count > 10000)
                    _events.RemoveRange(0, _events.Count - 5000);

                if (eventType == "blocked")
                {
                    _totalBlocked++;
                    _blockCounts.TryGetValue(domain, out var count);
                    _blockCounts[domain] = count + 1;
                }
            }

            if (_events.Count % 50 == 0)
                SaveEvents();
        }

        private void SaveEvents()
        {
            try
            {
                List<PhishingEvent> snapshot;
                lock (_lock) { snapshot = _events.TakeLast(1000).ToList(); }
                var json = JsonSerializer.Serialize(snapshot);
                File.WriteAllText(EventLogFile, json);
            }
            catch { }
        }

        private void LoadEvents()
        {
            if (!File.Exists(EventLogFile)) return;
            try
            {
                var json = File.ReadAllText(EventLogFile);
                var events = JsonSerializer.Deserialize<List<PhishingEvent>>(json);
                if (events != null)
                {
                    lock (_lock) { _events.AddRange(events); }
                }
            }
            catch { }
        }

        #endregion
    }

    public class PhishingEvent
    {
        public string Type { get; set; } = "";
        public string Domain { get; set; } = "";
        public string Detail { get; set; } = "";
        public DateTime Timestamp { get; set; }
    }

    public class DomainAnalysis
    {
        public string Domain { get; set; } = "";
        public bool IsBlocked { get; set; }
        public RiskLevel RiskLevel { get; set; }
        public int RiskScore { get; set; }
        public List<string> Reasons { get; set; } = new();
    }

    public enum RiskLevel
    {
        Safe,
        Low,
        Medium,
        High,
        Critical
    }
}
