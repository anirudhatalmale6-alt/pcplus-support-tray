using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using PCPlus.Core.Interfaces;
using PCPlus.Core.Models;

namespace PCPlus.Service.Modules.Phishing
{
    public class DnsFilterProxy : IDisposable
    {
        private const string ModuleName = "dns-proxy";
        private const int DnsPort = 53;
        private const int MaxPacketSize = 512;

        private IModuleContext _context = null!;
        private UdpClient? _listener;
        private CancellationTokenSource? _cts;
        private Task? _listenTask;
        private bool _isActive;

        private readonly IPEndPoint _upstreamDns1 = new(IPAddress.Parse("1.1.1.1"), DnsPort);
        private readonly IPEndPoint _upstreamDns2 = new(IPAddress.Parse("8.8.8.8"), DnsPort);

        private readonly ConcurrentDictionary<string, CachedDnsResult> _cache = new();
        private readonly ConcurrentDictionary<string, bool> _blocklist = new();

        private Func<string, bool>? _isBlocked;
        private int _totalQueries;
        private int _blockedQueries;
        private int _cachedResponses;
        private string? _originalDns;

        public void Start(IModuleContext context, Func<string, bool> blockChecker)
        {
            _context = context;
            _isBlocked = blockChecker;
            _cts = new CancellationTokenSource();

            try
            {
                SaveOriginalDns();
                StartListener();
                SetLocalDns();
                _isActive = true;
                _context.Log(LogLevel.Info, ModuleName,
                    "DNS filter proxy active on 127.0.0.1:53. All DNS queries are now filtered.");
            }
            catch (Exception ex)
            {
                _context.Log(LogLevel.Error, ModuleName, $"Failed to start DNS proxy: {ex.Message}");
                _isActive = false;
            }
        }

        public void Dispose()
        {
            _isActive = false;
            _cts?.Cancel();
            _listener?.Close();
            _listener?.Dispose();
            RestoreOriginalDns();
        }

        public bool IsActive => _isActive;
        public (int total, int blocked, int cached) GetStats() => (_totalQueries, _blockedQueries, _cachedResponses);

        private void StartListener()
        {
            _listener = new UdpClient(new IPEndPoint(IPAddress.Loopback, DnsPort));
            _listenTask = Task.Run(ListenLoop);
        }

        private async Task ListenLoop()
        {
            while (!_cts!.Token.IsCancellationRequested)
            {
                try
                {
                    var result = await _listener!.ReceiveAsync(_cts.Token);
                    _ = Task.Run(() => ProcessQuery(result.Buffer, result.RemoteEndPoint));
                }
                catch (OperationCanceledException) { break; }
                catch (ObjectDisposedException) { break; }
                catch { }
            }
        }

        private void ProcessQuery(byte[] query, IPEndPoint clientEndpoint)
        {
            try
            {
                _totalQueries++;
                var domain = ExtractDomainFromQuery(query);
                if (string.IsNullOrEmpty(domain)) return;

                // Check cache first
                if (_cache.TryGetValue(domain, out var cached) &&
                    cached.ExpiresAt > DateTime.UtcNow)
                {
                    _cachedResponses++;
                    var cachedResponse = BuildResponse(query, cached.ResponseData);
                    _listener?.Send(cachedResponse, cachedResponse.Length, clientEndpoint);
                    return;
                }

                // Check blocklist
                bool blocked = _blocklist.ContainsKey(domain);
                if (!blocked && _isBlocked != null)
                    blocked = _isBlocked(domain);

                if (blocked)
                {
                    _blockedQueries++;
                    var blockedResponse = BuildBlockedResponse(query);
                    _listener?.Send(blockedResponse, blockedResponse.Length, clientEndpoint);

                    _context.RaiseAlert(new Alert
                    {
                        ModuleId = ModuleName,
                        Title = "DNS Query Blocked",
                        Message = $"Blocked DNS lookup for: {domain}",
                        Severity = AlertSeverity.Warning,
                        Category = "dns-filter",
                        Metadata = new() { ["domain"] = domain }
                    });

                    LogQuery(domain, true);
                    return;
                }

                // Forward to upstream DNS
                var response = ForwardQuery(query);
                if (response != null)
                {
                    _listener?.Send(response, response.Length, clientEndpoint);

                    // Cache the response (5 minute TTL)
                    _cache[domain] = new CachedDnsResult
                    {
                        ResponseData = response,
                        ExpiresAt = DateTime.UtcNow.AddMinutes(5)
                    };
                }

                LogQuery(domain, false);
            }
            catch { }
        }

        private byte[]? ForwardQuery(byte[] query)
        {
            try
            {
                using var forwarder = new UdpClient();
                forwarder.Client.ReceiveTimeout = 3000;

                forwarder.Send(query, query.Length, _upstreamDns1);
                var remoteEp = new IPEndPoint(IPAddress.Any, 0);
                return forwarder.Receive(ref remoteEp);
            }
            catch
            {
                // Fallback to secondary DNS
                try
                {
                    using var forwarder = new UdpClient();
                    forwarder.Client.ReceiveTimeout = 3000;
                    forwarder.Send(query, query.Length, _upstreamDns2);
                    var remoteEp = new IPEndPoint(IPAddress.Any, 0);
                    return forwarder.Receive(ref remoteEp);
                }
                catch { return null; }
            }
        }

        private static string ExtractDomainFromQuery(byte[] packet)
        {
            try
            {
                if (packet.Length < 12) return "";

                int offset = 12; // Skip DNS header
                var parts = new List<string>();

                while (offset < packet.Length)
                {
                    int labelLen = packet[offset];
                    if (labelLen == 0) break;
                    if (offset + labelLen >= packet.Length) break;

                    offset++;
                    var label = System.Text.Encoding.ASCII.GetString(packet, offset, labelLen);
                    parts.Add(label);
                    offset += labelLen;
                }

                return parts.Count > 0 ? string.Join(".", parts).ToLowerInvariant() : "";
            }
            catch { return ""; }
        }

        private static byte[] BuildBlockedResponse(byte[] query)
        {
            // Build a DNS response pointing to 0.0.0.0
            var response = new byte[query.Length + 16];
            Array.Copy(query, response, query.Length);

            // Set response flags
            response[2] = 0x81; // QR=1, RD=1
            response[3] = 0x80; // RA=1
            response[6] = 0x00; // ANCOUNT high
            response[7] = 0x01; // ANCOUNT = 1

            // Answer section: pointer to domain name in question
            int answerOffset = query.Length;
            response[answerOffset] = 0xC0;     // Pointer
            response[answerOffset + 1] = 0x0C; // Offset to question name
            response[answerOffset + 2] = 0x00; // Type A
            response[answerOffset + 3] = 0x01;
            response[answerOffset + 4] = 0x00; // Class IN
            response[answerOffset + 5] = 0x01;
            response[answerOffset + 6] = 0x00; // TTL
            response[answerOffset + 7] = 0x00;
            response[answerOffset + 8] = 0x00;
            response[answerOffset + 9] = 0x3C; // 60 seconds
            response[answerOffset + 10] = 0x00; // RDLENGTH
            response[answerOffset + 11] = 0x04; // 4 bytes (IPv4)
            response[answerOffset + 12] = 0x00; // 0.0.0.0
            response[answerOffset + 13] = 0x00;
            response[answerOffset + 14] = 0x00;
            response[answerOffset + 15] = 0x00;

            return response[..(answerOffset + 16)];
        }

        private static byte[] BuildResponse(byte[] originalQuery, byte[] cachedResponse)
        {
            // Replace transaction ID from original query
            var response = (byte[])cachedResponse.Clone();
            response[0] = originalQuery[0];
            response[1] = originalQuery[1];
            return response;
        }

        public void AddToBlocklist(string domain)
        {
            _blocklist[domain.ToLowerInvariant()] = true;
        }

        public void RemoveFromBlocklist(string domain)
        {
            _blocklist.TryRemove(domain.ToLowerInvariant(), out _);
        }

        public void LoadBlocklist(IEnumerable<string> domains)
        {
            foreach (var d in domains)
                _blocklist[d.ToLowerInvariant()] = true;
        }

        private void SaveOriginalDns()
        {
            try
            {
                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = "interface ip show dns",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true
                };
                using var proc = System.Diagnostics.Process.Start(psi);
                _originalDns = proc?.StandardOutput.ReadToEnd();
                proc?.WaitForExit(5000);

                // Parse first configured DNS server
                if (_originalDns != null)
                {
                    foreach (var line in _originalDns.Split('\n'))
                    {
                        var trimmed = line.Trim();
                        if (IPAddress.TryParse(trimmed, out var ip) && !IPAddress.IsLoopback(ip))
                        {
                            _originalDns = ip.ToString();
                            break;
                        }
                    }
                }

                _context.Log(LogLevel.Info, ModuleName, $"Saved original DNS: {_originalDns}");
            }
            catch { _originalDns = "1.1.1.1"; }
        }

        private void SetLocalDns()
        {
            try
            {
                // Get active network interface name
                var interfaces = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces()
                    .Where(n => n.OperationalStatus == System.Net.NetworkInformation.OperationalStatus.Up
                        && n.NetworkInterfaceType != System.Net.NetworkInformation.NetworkInterfaceType.Loopback)
                    .ToList();

                foreach (var nic in interfaces)
                {
                    var name = nic.Name;
                    RunNetsh($"interface ip set dns name=\"{name}\" static 127.0.0.1 primary");
                    _context.Log(LogLevel.Info, ModuleName, $"Set DNS to 127.0.0.1 on interface: {name}");
                }
            }
            catch (Exception ex)
            {
                _context.Log(LogLevel.Error, ModuleName, $"Failed to set local DNS: {ex.Message}");
            }
        }

        private void RestoreOriginalDns()
        {
            try
            {
                var interfaces = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces()
                    .Where(n => n.OperationalStatus == System.Net.NetworkInformation.OperationalStatus.Up
                        && n.NetworkInterfaceType != System.Net.NetworkInformation.NetworkInterfaceType.Loopback)
                    .ToList();

                foreach (var nic in interfaces)
                {
                    var name = nic.Name;
                    // Restore to DHCP
                    RunNetsh($"interface ip set dns name=\"{name}\" dhcp");
                }

                _context.Log(LogLevel.Info, ModuleName, "DNS restored to DHCP");
            }
            catch (Exception ex)
            {
                _context.Log(LogLevel.Warning, ModuleName, $"Failed to restore DNS: {ex.Message}");
            }
        }

        private static void RunNetsh(string arguments)
        {
            try
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = arguments,
                    UseShellExecute = false,
                    CreateNoWindow = true
                })?.WaitForExit(5000);
            }
            catch { }
        }

        private void LogQuery(string domain, bool blocked)
        {
            // Periodic cache cleanup
            if (_totalQueries % 1000 == 0)
            {
                var expired = _cache.Where(kv => kv.Value.ExpiresAt < DateTime.UtcNow)
                    .Select(kv => kv.Key).ToList();
                foreach (var key in expired) _cache.TryRemove(key, out _);
            }
        }
    }

    internal class CachedDnsResult
    {
        public byte[] ResponseData { get; set; } = Array.Empty<byte>();
        public DateTime ExpiresAt { get; set; }
    }
}
