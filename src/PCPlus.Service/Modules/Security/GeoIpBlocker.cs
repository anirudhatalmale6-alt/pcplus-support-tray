using System.Diagnostics;
using System.Net;
using System.Text.Json;
using PCPlus.Core.Interfaces;
using PCPlus.Core.Models;

namespace PCPlus.Service.Modules.Security
{
    public class GeoIpBlocker : IDisposable
    {
        private const string ModuleName = "geoip";
        private static readonly string DataDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "PCPlusEndpoint");
        private static readonly string CachePath = Path.Combine(DataDir, "geoip-cache.json");

        private IModuleContext _context = null!;
        private Timer? _scanTimer;
        private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(5) };
        private readonly Dictionary<string, string> _ipCountryCache = new();
        private readonly HashSet<string> _alreadyBlocked = new();
        private int _blockedCount;
        private int _scannedCount;

        // Countries commonly associated with cyber attacks
        // Configurable via config.json in future
        private static readonly HashSet<string> BlockedCountryCodes = new(StringComparer.OrdinalIgnoreCase)
        {
            "RU", // Russia
            "CN", // China
            "KP", // North Korea
            "IR", // Iran
            "NG", // Nigeria (high phishing)
        };

        // Countries that are always allowed (never block)
        private static readonly HashSet<string> AllowedCountryCodes = new(StringComparer.OrdinalIgnoreCase)
        {
            "CA", // Canada
            "US", // United States
            "GB", // United Kingdom
            "DE", // Germany
            "FR", // France
            "AU", // Australia
            "NL", // Netherlands (CDNs)
            "IE", // Ireland (cloud providers)
            "SG", // Singapore (cloud providers)
            "JP", // Japan
        };

        // Well-known IPs that should never be looked up
        private static readonly string[] SkipPrefixes = new[]
        {
            "10.", "172.16.", "172.17.", "172.18.", "172.19.",
            "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
            "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
            "172.30.", "172.31.", "192.168.", "127.", "0.", "169.254."
        };

        public void Start(IModuleContext context)
        {
            _context = context;
            LoadCache();

            // Scan connections every 60 seconds
            _scanTimer = new Timer(_ => ScanConnections(), null,
                TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(60));

            _context.Log(LogLevel.Info, ModuleName,
                $"Geo-IP blocker active. Blocking: {string.Join(", ", BlockedCountryCodes)}");
        }

        public void Dispose()
        {
            _scanTimer?.Dispose();
            _http.Dispose();
            SaveCache();
        }

        public (int scanned, int blocked) GetStats() => (_scannedCount, _blockedCount);

        private void ScanConnections()
        {
            try
            {
                var output = RunNetstat();
                var foreignIps = ExtractForeignIps(output);

                foreach (var ip in foreignIps)
                {
                    if (_alreadyBlocked.Contains(ip)) continue;
                    if (IsPrivateIp(ip)) continue;
                    if (_ipCountryCache.TryGetValue(ip, out var cachedCountry))
                    {
                        if (BlockedCountryCodes.Contains(cachedCountry))
                            BlockIp(ip, cachedCountry);
                        continue;
                    }

                    _scannedCount++;
                    var country = LookupCountry(ip);
                    if (string.IsNullOrEmpty(country)) continue;

                    _ipCountryCache[ip] = country;

                    if (BlockedCountryCodes.Contains(country) && !AllowedCountryCodes.Contains(country))
                    {
                        BlockIp(ip, country);
                    }
                }

                // Periodic cache cleanup
                if (_ipCountryCache.Count > 10000)
                {
                    var toRemove = _ipCountryCache.Keys.Take(5000).ToList();
                    foreach (var key in toRemove) _ipCountryCache.Remove(key);
                }
            }
            catch (Exception ex)
            {
                _context.Log(LogLevel.Warning, ModuleName, $"Scan error: {ex.Message}");
            }
        }

        private void BlockIp(string ip, string country)
        {
            if (!_alreadyBlocked.Add(ip)) return;
            _blockedCount++;

            _context.RaiseAlert(new Alert
            {
                ModuleId = ModuleName,
                Title = "Blocked Connection from High-Risk Country",
                Message = $"Connection to {ip} blocked (country: {country})",
                Severity = AlertSeverity.Warning,
                Category = "geoip",
                Metadata = new()
                {
                    ["ip"] = ip,
                    ["country"] = country
                }
            });

            _context.Log(LogLevel.Warning, ModuleName,
                $"Blocked: {ip} ({country})");

            // Add Windows Firewall rule to block the IP
            try
            {
                RunCmd("netsh",
                    $"advfirewall firewall add rule name=\"PCPlus-GeoBlock-{ip}\" " +
                    $"dir=out action=block remoteip={ip} enable=yes");
                RunCmd("netsh",
                    $"advfirewall firewall add rule name=\"PCPlus-GeoBlock-{ip}-In\" " +
                    $"dir=in action=block remoteip={ip} enable=yes");
            }
            catch { }
        }

        private string LookupCountry(string ip)
        {
            try
            {
                // Use ip-api.com (free, no key needed, 45 req/min)
                var request = new HttpRequestMessage(HttpMethod.Get,
                    $"http://ip-api.com/json/{ip}?fields=countryCode,status");
                var response = _http.Send(request);

                if (!response.IsSuccessStatusCode) return "";

                using var stream = response.Content.ReadAsStream();
                var doc = JsonDocument.Parse(stream);
                var root = doc.RootElement;

                if (root.TryGetProperty("status", out var status) &&
                    status.GetString() == "success" &&
                    root.TryGetProperty("countryCode", out var cc))
                {
                    return cc.GetString() ?? "";
                }
            }
            catch { }
            return "";
        }

        private static bool IsPrivateIp(string ip)
        {
            foreach (var prefix in SkipPrefixes)
            {
                if (ip.StartsWith(prefix)) return true;
            }
            return false;
        }

        private static HashSet<string> ExtractForeignIps(string netstatOutput)
        {
            var ips = new HashSet<string>();
            foreach (var line in netstatOutput.Split('\n'))
            {
                if (!line.Contains("ESTABLISHED") && !line.Contains("SYN_SENT"))
                    continue;

                var parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 3) continue;

                var foreign = parts[2];
                var colonIdx = foreign.LastIndexOf(':');
                if (colonIdx <= 0) continue;

                var host = foreign[..colonIdx];
                if (IPAddress.TryParse(host, out _))
                    ips.Add(host);
            }
            return ips;
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

        private void SaveCache()
        {
            try
            {
                Directory.CreateDirectory(DataDir);
                var json = JsonSerializer.Serialize(_ipCountryCache);
                File.WriteAllText(CachePath, json);
            }
            catch { }
        }

        private void LoadCache()
        {
            try
            {
                if (!File.Exists(CachePath)) return;
                var json = File.ReadAllText(CachePath);
                var data = JsonSerializer.Deserialize<Dictionary<string, string>>(json);
                if (data != null)
                    foreach (var kv in data) _ipCountryCache[kv.Key] = kv.Value;
            }
            catch { }
        }
    }
}
