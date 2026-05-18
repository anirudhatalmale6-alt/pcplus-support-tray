using System.Net;
using System.Net.Http.Headers;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using PCPlus.Core.Models;

namespace PCPlus.Service.Engine
{
    public class AdGuardClient
    {
        private readonly HttpClient _http;
        private readonly string _baseUrl;
        private DnsStatsDto? _cachedStats;
        private DateTime _cacheExpiry;
        private readonly SemaphoreSlim _fetchLock = new(1, 1);

        public AdGuardClient(string baseUrl, string user, string password)
        {
            _baseUrl = baseUrl.TrimEnd('/');
            var handler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (_, _, _, _) => true
            };
            _http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(15) };
            var creds = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{user}:{password}"));
            _http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", creds);
        }

        public async Task<DnsStatsDto> GetStatsForThisMachineAsync()
        {
            if (_cachedStats != null && DateTime.UtcNow < _cacheExpiry)
                return _cachedStats;

            if (!await _fetchLock.WaitAsync(0))
                return _cachedStats ?? new DnsStatsDto();

            try
            {
                var result = new DnsStatsDto { FetchedAt = DateTime.UtcNow };
                var clientIp = GetLocalIpAddress();
                result.ClientIp = clientIp;

                var overallTask = FetchOverallStatsAsync();
                var queryLogTask = string.IsNullOrEmpty(clientIp)
                    ? Task.FromResult<List<QueryLogEntry>?>(null)
                    : FetchQueryLogAsync(clientIp, 1000);

                await Task.WhenAll(overallTask, queryLogTask);

                var overall = overallTask.Result;
                var clientLog = queryLogTask.Result;

                if (overall != null)
                {
                    result.GlobalTotalQueries = overall.NumDnsQueries;
                    result.GlobalBlockedQueries = overall.NumBlockedFiltering;
                    result.FilterListCount = overall.NumReplacedSafebrowsing + overall.NumBlockedFiltering;

                    if (overall.TopBlockedDomains != null)
                    {
                        result.GlobalTopBlocked = overall.TopBlockedDomains
                            .SelectMany(d => d)
                            .Take(10)
                            .Select(kv => new DnsStatDomainDto { Domain = kv.Key, Count = (int)kv.Value })
                            .ToList();
                    }
                }

                if (clientLog != null && clientLog.Count > 0)
                {
                    result.ClientTotalQueries = clientLog.Count;
                    result.ClientBlockedQueries = clientLog.Count(e =>
                        e.Reason == "FilteredBlackList" ||
                        e.Reason == "FilteredBlockedService" ||
                        e.Reason == "FilteredSafeBrowsing" ||
                        e.Reason == "FilteredParental");

                    result.ClientTopBlocked = clientLog
                        .Where(e => e.Reason == "FilteredBlackList" ||
                                    e.Reason == "FilteredBlockedService" ||
                                    e.Reason == "FilteredSafeBrowsing")
                        .GroupBy(e => e.Question?.Name ?? "unknown")
                        .OrderByDescending(g => g.Count())
                        .Take(10)
                        .Select(g => new DnsStatDomainDto { Domain = g.Key.TrimEnd('.'), Count = g.Count() })
                        .ToList();

                    result.ClientTopQueried = clientLog
                        .GroupBy(e => e.Question?.Name ?? "unknown")
                        .OrderByDescending(g => g.Count())
                        .Take(10)
                        .Select(g => new DnsStatDomainDto { Domain = g.Key.TrimEnd('.'), Count = g.Count() })
                        .ToList();

                    var latest = clientLog
                        .Where(e => e.Reason == "FilteredBlackList")
                        .OrderByDescending(e => e.Time)
                        .FirstOrDefault();
                    if (latest != null)
                        result.LastBlockedDomain = latest.Question?.Name?.TrimEnd('.') ?? "";

                    result.HasClientData = true;
                }

                _cachedStats = result;
                _cacheExpiry = DateTime.UtcNow.AddMinutes(3);
                return result;
            }
            catch (Exception ex)
            {
                return new DnsStatsDto { Error = ex.Message };
            }
            finally
            {
                _fetchLock.Release();
            }
        }

        private async Task<OverallStats?> FetchOverallStatsAsync()
        {
            try
            {
                var resp = await _http.GetAsync($"{_baseUrl}/control/stats");
                if (!resp.IsSuccessStatusCode) return null;
                var json = await resp.Content.ReadAsStringAsync();
                return JsonSerializer.Deserialize<OverallStats>(json, JsonOpts);
            }
            catch { return null; }
        }

        private async Task<List<QueryLogEntry>?> FetchQueryLogAsync(string clientIp, int limit)
        {
            try
            {
                var url = $"{_baseUrl}/control/querylog?search={Uri.EscapeDataString(clientIp)}&limit={limit}";
                var resp = await _http.GetAsync(url);
                if (!resp.IsSuccessStatusCode) return null;
                var json = await resp.Content.ReadAsStringAsync();
                var result = JsonSerializer.Deserialize<QueryLogResponse>(json, JsonOpts);
                return result?.Data;
            }
            catch { return null; }
        }

        private static string GetLocalIpAddress()
        {
            try
            {
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus != OperationalStatus.Up) continue;
                    if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                    if (ni.NetworkInterfaceType == NetworkInterfaceType.Tunnel) continue;

                    var props = ni.GetIPProperties();
                    if (props.GatewayAddresses.Count == 0) continue;

                    foreach (var addr in props.UnicastAddresses)
                    {
                        if (addr.Address.AddressFamily == AddressFamily.InterNetwork)
                            return addr.Address.ToString();
                    }
                }
            }
            catch { }
            return "";
        }

        private static readonly JsonSerializerOptions JsonOpts = new()
        {
            PropertyNameCaseInsensitive = true,
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
        };
    }

    internal class OverallStats
    {
        [JsonPropertyName("num_dns_queries")]
        public long NumDnsQueries { get; set; }
        [JsonPropertyName("num_blocked_filtering")]
        public long NumBlockedFiltering { get; set; }
        [JsonPropertyName("num_replaced_safebrowsing")]
        public long NumReplacedSafebrowsing { get; set; }
        [JsonPropertyName("top_blocked_domains")]
        public List<Dictionary<string, long>>? TopBlockedDomains { get; set; }
        [JsonPropertyName("top_queried_domains")]
        public List<Dictionary<string, long>>? TopQueriedDomains { get; set; }
    }

    internal class QueryLogResponse
    {
        public List<QueryLogEntry>? Data { get; set; }
    }

    internal class QueryLogEntry
    {
        public string? Reason { get; set; }
        public string? Client { get; set; }
        public DateTime Time { get; set; }
        public QueryLogQuestion? Question { get; set; }
    }

    internal class QueryLogQuestion
    {
        public string? Name { get; set; }
        public string? Type { get; set; }
    }
}
