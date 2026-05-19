using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;
using PCPlus.Core.Interfaces;
using PCPlus.Core.Models;

namespace PCPlus.Service.Modules.Phishing
{
    public class UrlReputationEngine : IDisposable
    {
        private IModuleContext _context = null!;
        private Timer? _connectionMonitor;
        private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(10) };
        private readonly ConcurrentDictionary<string, DomainReputation> _cache = new();
        private readonly HashSet<string> _whitelistedDomains = new(StringComparer.OrdinalIgnoreCase);
        private int _blockedCount;
        private int _scannedCount;

        private static readonly string[] SuspiciousPatterns = new[]
        {
            "login", "signin", "sign-in", "verify", "verification",
            "secure", "security", "account", "update", "confirm",
            "authenticate", "password", "credential", "unlock",
            "suspended", "limited", "restore", "recover", "invoice",
            "payment", "billing", "refund", "shipping", "delivery"
        };

        private static readonly string[] TargetBrands = new[]
        {
            "microsoft", "google", "apple", "amazon", "paypal",
            "facebook", "netflix", "chase", "wellsfargo", "bankofamerica",
            "citibank", "dropbox", "adobe", "linkedin", "twitter",
            "instagram", "outlook", "office365", "onedrive", "icloud",
            "walmart", "costco", "bestbuy", "usps", "fedex", "ups",
            "dhl", "canadapost", "royalbank", "td", "scotiabank", "bmo"
        };

        private static readonly string[] FreeHostingProviders = new[]
        {
            "000webhostapp.com", "weebly.com", "wixsite.com",
            "blogspot.com", "wordpress.com", "sites.google.com",
            "github.io", "netlify.app", "vercel.app", "herokuapp.com",
            "web.app", "firebaseapp.com", "glitch.me", "replit.co"
        };

        private static readonly string[] HighRiskTLDs = new[]
        {
            ".xyz", ".top", ".club", ".online", ".site", ".icu",
            ".buzz", ".tk", ".ml", ".ga", ".cf", ".gq",
            ".wang", ".work", ".click", ".link", ".info"
        };

        public void Start(IModuleContext context)
        {
            _context = context;

            if (!_context.Config.UrlReputationEnabled)
            {
                _context.Log(LogLevel.Info, "phishing", "URL Reputation Engine disabled in config");
                return;
            }

            LoadWhitelist();

            var intervalSeconds = _context.Config.UrlReputationIntervalSeconds;
            _connectionMonitor = new Timer(_ => ScanActiveConnections(), null,
                TimeSpan.FromSeconds(intervalSeconds), TimeSpan.FromSeconds(intervalSeconds));

            _context.Log(LogLevel.Info, "phishing",
                "URL Reputation Engine active: real-time connection scanning");
        }

        public void Dispose()
        {
            _connectionMonitor?.Dispose();
            _http.Dispose();
        }

        public (int scanned, int blocked) GetStats() => (_scannedCount, _blockedCount);

        private void ScanActiveConnections()
        {
            try
            {
                var output = RunNetstat();
                var domains = ExtractDomainsFromConnections(output);

                foreach (var domain in domains)
                {
                    if (_whitelistedDomains.Contains(domain)) continue;
                    if (_cache.TryGetValue(domain, out var cached) && cached.CheckedAt > DateTime.UtcNow.AddHours(-1))
                        continue;

                    _scannedCount++;
                    var rep = ScoreDomain(domain);
                    _cache[domain] = rep;

                    if (rep.TotalScore >= 60)
                    {
                        _blockedCount++;
                        _context.RaiseAlert(new Alert
                        {
                            ModuleId = "phishing",
                            Title = "Suspicious URL Detected",
                            Message = $"High-risk domain: {domain} (score: {rep.TotalScore}/100). Reasons: {string.Join(", ", rep.Reasons)}",
                            Severity = rep.TotalScore >= 80 ? AlertSeverity.Critical : AlertSeverity.Warning,
                            Category = "phishing",
                            Metadata = new()
                            {
                                ["domain"] = domain,
                                ["score"] = rep.TotalScore.ToString(),
                                ["reasons"] = string.Join("; ", rep.Reasons)
                            }
                        });

                        _context.Log(LogLevel.Warning, "phishing",
                            $"URL Reputation: {domain} scored {rep.TotalScore}/100 - {string.Join(", ", rep.Reasons)}");

                        BlockDomain(domain);
                    }
                }

                CleanCache();
            }
            catch (Exception ex)
            {
                _context.Log(LogLevel.Warning, "phishing", $"URL scan error: {ex.Message}");
            }
        }

        private DomainReputation ScoreDomain(string domain)
        {
            var rep = new DomainReputation { Domain = domain, CheckedAt = DateTime.UtcNow };
            var lowerDomain = domain.ToLowerInvariant();

            // 1. Check for suspicious URL patterns (brand + action words)
            foreach (var brand in TargetBrands)
            {
                if (lowerDomain.Contains(brand) && !lowerDomain.EndsWith($".{brand}.com")
                    && !lowerDomain.EndsWith($".{brand}.ca")
                    && !lowerDomain.EndsWith($".{brand}.co.uk"))
                {
                    rep.TotalScore += 30;
                    rep.Reasons.Add($"Contains brand name '{brand}' in non-official domain");
                    break;
                }
            }

            foreach (var pattern in SuspiciousPatterns)
            {
                if (lowerDomain.Contains(pattern))
                {
                    rep.TotalScore += 15;
                    rep.Reasons.Add($"Suspicious keyword '{pattern}' in domain");
                    break;
                }
            }

            // 2. Check for high-risk TLDs
            foreach (var tld in HighRiskTLDs)
            {
                if (lowerDomain.EndsWith(tld))
                {
                    rep.TotalScore += 15;
                    rep.Reasons.Add($"High-risk TLD: {tld}");
                    break;
                }
            }

            // 3. Check for free hosting
            foreach (var host in FreeHostingProviders)
            {
                if (lowerDomain.EndsWith(host) || lowerDomain.Contains(host))
                {
                    rep.TotalScore += 20;
                    rep.Reasons.Add($"Free hosting provider: {host}");
                    break;
                }
            }

            // 4. Check domain characteristics
            if (lowerDomain.Count(c => c == '-') >= 3)
            {
                rep.TotalScore += 15;
                rep.Reasons.Add("Excessive hyphens in domain");
            }

            if (lowerDomain.Count(c => c == '.') >= 4)
            {
                rep.TotalScore += 10;
                rep.Reasons.Add("Excessive subdomains");
            }

            if (Regex.IsMatch(lowerDomain, @"\d{4,}"))
            {
                rep.TotalScore += 10;
                rep.Reasons.Add("Long numeric sequence in domain");
            }

            // 5. Very long domain names are suspicious
            var mainDomain = GetMainDomain(lowerDomain);
            if (mainDomain.Length > 30)
            {
                rep.TotalScore += 10;
                rep.Reasons.Add("Unusually long domain name");
            }

            // 6. Check for IP address as hostname
            if (IPAddress.TryParse(domain, out _))
            {
                rep.TotalScore += 25;
                rep.Reasons.Add("Direct IP address connection (no domain)");
            }

            // 7. Homoglyph/lookalike detection
            if (ContainsHomoglyphs(lowerDomain))
            {
                rep.TotalScore += 30;
                rep.Reasons.Add("Contains lookalike characters (possible homoglyph attack)");
            }

            rep.TotalScore = Math.Min(rep.TotalScore, 100);
            return rep;
        }

        private static bool ContainsHomoglyphs(string domain)
        {
            foreach (var c in domain)
            {
                if (c > 127) return true; // Non-ASCII character in domain
            }

            // Check for common substitutions in brand contexts
            var normalized = domain
                .Replace("0", "o").Replace("1", "l").Replace("5", "s")
                .Replace("8", "b").Replace("3", "e").Replace("4", "a");

            return normalized != domain && TargetBrands.Any(b => normalized.Contains(b));
        }

        private void BlockDomain(string domain)
        {
            try
            {
                var hostsPath = @"C:\Windows\System32\drivers\etc\hosts";
                var entry = $"0.0.0.0 {domain}";
                var lines = File.ReadAllLines(hostsPath);
                if (lines.Any(l => l.Contains(domain))) return;

                File.AppendAllText(hostsPath, $"\n{entry} # PCPlus-blocked\n");
                RunCmd("ipconfig", "/flushdns");
            }
            catch { }
        }

        private static string RunNetstat()
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "netstat",
                    Arguments = "-n",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true
                };
                using var proc = Process.Start(psi);
                var output = proc?.StandardOutput.ReadToEnd() ?? "";
                proc?.WaitForExit(5000);
                return output;
            }
            catch { return ""; }
        }

        private static HashSet<string> ExtractDomainsFromConnections(string netstatOutput)
        {
            var domains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var line in netstatOutput.Split('\n'))
            {
                if (!line.Contains("ESTABLISHED")) continue;
                var parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 3) continue;

                var foreign = parts[2];
                var colonIdx = foreign.LastIndexOf(':');
                if (colonIdx <= 0) continue;

                var host = foreign[..colonIdx];
                if (!IPAddress.TryParse(host, out _)) continue;

                // Reverse DNS lookup for the IP
                try
                {
                    var entry = Dns.GetHostEntry(host);
                    if (!string.IsNullOrEmpty(entry.HostName) && entry.HostName != host)
                        domains.Add(entry.HostName);
                }
                catch { }
            }
            return domains;
        }

        private static string GetMainDomain(string domain)
        {
            var parts = domain.Split('.');
            return parts.Length >= 2 ? $"{parts[^2]}.{parts[^1]}" : domain;
        }

        private void LoadWhitelist()
        {
            // Common legitimate domains that should never be blocked
            var safe = new[]
            {
                "microsoft.com", "google.com", "apple.com", "amazon.com",
                "amazonaws.com", "azure.com", "cloudflare.com", "akamai.net",
                "facebook.com", "instagram.com", "twitter.com", "linkedin.com",
                "github.com", "githubusercontent.com", "github.io", "githubassets.com",
                "stackoverflow.com", "reddit.com", "youtube.com",
                "netflix.com", "paypal.com", "chase.com", "wellsfargo.com",
                "bankofamerica.com", "citibank.com", "windows.com",
                "windowsupdate.com", "office.com", "office365.com",
                "live.com", "outlook.com", "onedrive.com", "sharepoint.com",
                "pcpluscomputing.com", "pcpluscomputing.ca", "tacticalrmm.com"
            };
            foreach (var d in safe) _whitelistedDomains.Add(d);
        }

        private void CleanCache()
        {
            var cutoff = DateTime.UtcNow.AddHours(-6);
            var stale = _cache.Where(kv => kv.Value.CheckedAt < cutoff).Select(kv => kv.Key).ToList();
            foreach (var key in stale) _cache.TryRemove(key, out _);
        }

        private static void RunCmd(string fileName, string arguments)
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = fileName,
                    Arguments = arguments,
                    UseShellExecute = false,
                    CreateNoWindow = true
                })?.WaitForExit(5000);
            }
            catch { }
        }
    }

    public class DomainReputation
    {
        public string Domain { get; set; } = "";
        public int TotalScore { get; set; }
        public List<string> Reasons { get; set; } = new();
        public DateTime CheckedAt { get; set; }
    }
}
