using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using PCPlus.Core.Interfaces;
using PCPlus.Core.Models;

namespace PCPlus.Service.Modules.Phishing
{
    public class DnsFilterProxy : IDisposable
    {
        private const string ModuleName = "dns-proxy";
        private const int DnsPort = 53;
        private const int DotPort = 853;
        private const int MaxUdpPacketSize = 4096;
        private const int MaxCacheEntries = 50000;
        private const int CacheCleanupThreshold = 5000;

        private IModuleContext _context = null!;
        private UdpClient? _listener;
        private CancellationTokenSource? _cts;
        #pragma warning disable CS0414
        private Thread? _listenThread;
        #pragma warning restore CS0414
        private Task? _watchdogTask;
        private Task? _cacheCleanupTask;
        private bool _isActive;

        // DNS-over-TLS upstream resolvers (primary + fallback)
        private static readonly DotResolver[] _dotResolvers = new[]
        {
            new DotResolver("1.1.1.1", "cloudflare-dns.com"),    // Cloudflare
            new DotResolver("1.0.0.1", "cloudflare-dns.com"),    // Cloudflare secondary
            new DotResolver("8.8.8.8", "dns.google"),            // Google
            new DotResolver("8.8.4.4", "dns.google"),            // Google secondary
            new DotResolver("9.9.9.9", "dns.quad9.net"),         // Quad9 (threat-blocking)
        };

        // Plain UDP fallback (fail-open scenario only)
        private readonly IPEndPoint _fallbackUdp1 = new(IPAddress.Parse("1.1.1.1"), DnsPort);
        private readonly IPEndPoint _fallbackUdp2 = new(IPAddress.Parse("8.8.8.8"), DnsPort);

        private readonly ConcurrentDictionary<string, CachedDnsResult> _cache = new();
        private readonly ConcurrentDictionary<string, bool> _blocklist = new();
        private readonly ConcurrentDictionary<string, DateTime> _poisonAttempts = new();

        // Critical domains that must never be blocked (infrastructure)
        private static readonly HashSet<string> _neverBlock = new(StringComparer.OrdinalIgnoreCase)
        {
            "github.com", "raw.githubusercontent.com", "githubusercontent.com",
            "github.io", "githubassets.com", "objects.githubusercontent.com",
            "microsoft.com", "windows.com", "windowsupdate.com",
            "google.com", "googleapis.com", "gstatic.com",
            "cloudflare.com", "cloudflare-dns.com",
            "apple.com", "icloud.com",
            "pcpluscomputing.com", "pcpluscomputing.ca",
            "tailscale.com", "login.tailscale.com",
        };

        private Func<string, bool>? _isBlocked;
        private Action<string, bool, string>? _onDnsQuery; // (domain, wasBlocked, reason)
        private long _totalQueries;
        private long _blockedQueries;
        private long _cachedResponses;
        private long _dotQueries;
        private long _udpFallbackQueries;
        private long _failedQueries;
        private long _antiBypassDetections;
        private long _cachePoisonAttempts;
        private string? _originalDns;
        private DateTime _lastWatchdogCheck = DateTime.MinValue;
        private bool _dotAvailable = false;
        private bool _dotConfigEnabled = true;

        public void Start(IModuleContext context, Func<string, bool> blockChecker, Action<string, bool, string>? onDnsQuery = null)
        {
            _context = context;
            _isBlocked = blockChecker;
            _onDnsQuery = onDnsQuery;
            _cts = new CancellationTokenSource();

            var dotSetting = _context.Config.GetValue("dnsOverTlsEnabled");
            _dotConfigEnabled = dotSetting == null || !string.Equals(dotSetting, "false", StringComparison.OrdinalIgnoreCase);

            try
            {
                SaveOriginalDns();
                StartListener();
                SetLocalDns();
                _isActive = true;

                // Start DNS settings watchdog (anti-bypass)
                _watchdogTask = Task.Run(DnsWatchdogLoop);

                // Start periodic cache cleanup
                _cacheCleanupTask = Task.Run(CacheCleanupLoop);

                if (_dotConfigEnabled)
                    _ = Task.Run(TestDotConnectivity);
                else
                    _context.Log(LogLevel.Info, ModuleName, "DNS-over-TLS disabled by config.");

                _context.Log(LogLevel.Info, ModuleName,
                    "DNS filter proxy v2.0 active on 127.0.0.1:53. Anti-bypass watchdog running.");
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
        public bool DotEnabled => _dotAvailable;

        public DnsProxyStats GetDetailedStats() => new()
        {
            TotalQueries = _totalQueries,
            BlockedQueries = _blockedQueries,
            CachedResponses = _cachedResponses,
            DotQueries = _dotQueries,
            UdpFallbackQueries = _udpFallbackQueries,
            FailedQueries = _failedQueries,
            AntiBypassDetections = _antiBypassDetections,
            CachePoisonAttempts = _cachePoisonAttempts,
            CacheSize = _cache.Count,
            BlocklistSize = _blocklist.Count,
            DotAvailable = _dotAvailable,
            IsActive = _isActive
        };

        public (int total, int blocked, int cached) GetStats() =>
            ((int)_totalQueries, (int)_blockedQueries, (int)_cachedResponses);

        #region Listener

        private void StartListener()
        {
            _listener = new UdpClient(new IPEndPoint(IPAddress.Loopback, DnsPort));
            _listener.Client.ReceiveBufferSize = 65536;
            _listener.Client.ReceiveTimeout = 500;

            try
            {
                const int SIO_UDP_CONNRESET = unchecked((int)0x9800000C);
                _listener.Client.IOControl(SIO_UDP_CONNRESET, new byte[] { 0 }, null);
            }
            catch { }

            var thread = new Thread(ListenLoopSync) { IsBackground = true, Priority = ThreadPriority.AboveNormal };
            thread.Start();
        }

        private DateTime _lastListenErrorLog = DateTime.MinValue;
        private long _listenErrorCount;

        private void ListenLoopSync()
        {
            while (!_cts!.Token.IsCancellationRequested)
            {
                try
                {
                    var remoteEp = new IPEndPoint(IPAddress.Any, 0);
                    byte[] buffer;
                    try { buffer = _listener!.Receive(ref remoteEp); }
                    catch (SocketException) { continue; }
                    ProcessQuerySafe(buffer, remoteEp);
                }
                catch (ObjectDisposedException) { break; }
                catch (Exception ex)
                {
                    Interlocked.Increment(ref _listenErrorCount);
                    if ((DateTime.UtcNow - _lastListenErrorLog).TotalSeconds > 60)
                    {
                        _lastListenErrorLog = DateTime.UtcNow;
                        _context.Log(LogLevel.Warning, ModuleName,
                            $"Listen errors: {_listenErrorCount} total. Latest: {ex.Message}");
                    }
                }
            }
        }

        #endregion

        #region Query Processing

        private void ProcessQuerySafe(byte[] query, IPEndPoint clientEndpoint)
        {
            try
            {
                ProcessQuery(query, clientEndpoint);
            }
            catch (Exception ex)
            {
                Interlocked.Increment(ref _failedQueries);

                // Fail-open: forward raw query to upstream UDP so the user isn't left without DNS
                try
                {
                    var response = ForwardQueryUdp(query);
                    if (response != null)
                        _listener?.Send(response, response.Length, clientEndpoint);
                }
                catch
                {
                    _context.Log(LogLevel.Error, ModuleName,
                        $"DNS query failed completely (fail-open also failed): {ex.Message}");
                }
            }
        }

        private void ProcessQuery(byte[] query, IPEndPoint clientEndpoint)
        {
            Interlocked.Increment(ref _totalQueries);
            var domain = ExtractDomainFromQuery(query);
            if (string.IsNullOrEmpty(domain)) return;

            var queryType = ExtractQueryType(query);

            // Cache lookup
            var cacheKey = $"{domain}:{queryType}";
            if (_cache.TryGetValue(cacheKey, out var cached) && cached.ExpiresAt > DateTime.UtcNow)
            {
                Interlocked.Increment(ref _cachedResponses);
                var cachedResponse = BuildCachedResponse(query, cached.ResponseData);
                _listener?.Send(cachedResponse, cachedResponse.Length, clientEndpoint);
                return;
            }

            // Never block critical infrastructure domains
            bool whitelisted = _neverBlock.Contains(domain) ||
                _neverBlock.Any(nb => domain.EndsWith("." + nb, StringComparison.OrdinalIgnoreCase));

            if (!whitelisted)
            {
                // Blocklist check
                bool blocked = _blocklist.ContainsKey(domain);
                if (!blocked && _isBlocked != null)
                    blocked = _isBlocked(domain);

                // Also check parent domains (e.g., block sub.evil.com if evil.com is blocked)
                if (!blocked)
                    blocked = IsParentDomainBlocked(domain);

                if (blocked)
                {
                    Interlocked.Increment(ref _blockedQueries);
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

                    try { _onDnsQuery?.Invoke(domain, true, "DNS blocklist match"); } catch { }
                    return;
                }
            }

            // Notify: query processed, not blocked
            try { _onDnsQuery?.Invoke(domain, false, ""); } catch { }

            // Forward to upstream (prefer DoT, fallback to UDP)
            byte[]? response = null;

            if (_dotConfigEnabled && _dotAvailable)
            {
                response = ForwardQueryDoT(query);
                if (response != null)
                    Interlocked.Increment(ref _dotQueries);
            }

            if (response == null)
            {
                response = ForwardQueryUdp(query);
                if (response != null)
                    Interlocked.Increment(ref _udpFallbackQueries);
            }

            if (response != null)
            {
                // Cache poisoning detection (skip for PTR/reverse DNS - causes false positives)
                bool skipValidation = queryType == 12 || domain.EndsWith(".in-addr.arpa") ||
                    domain.EndsWith(".ip6.arpa") || domain.EndsWith(".local");
                if (!skipValidation && !ValidateResponse(response, domain, queryType))
                {
                    Interlocked.Increment(ref _cachePoisonAttempts);
                    _poisonAttempts[domain] = DateTime.UtcNow;
                    _context.Log(LogLevel.Warning, ModuleName,
                        $"Possible cache poisoning detected for {domain}. Response discarded.");
                    _context.RaiseAlert(new Alert
                    {
                        ModuleId = ModuleName,
                        Title = "DNS Cache Poisoning Attempt",
                        Message = $"Suspicious DNS response for {domain} was discarded.",
                        Severity = AlertSeverity.Critical,
                        Category = "dns-security",
                        Metadata = new() { ["domain"] = domain }
                    });

                    // Retry with a different resolver
                    response = ForwardQueryUdp(query, useSecondary: true);
                    if (response == null) return;
                }

                _listener?.Send(response, response.Length, clientEndpoint);

                // Cache with TTL from response (capped at 5 minutes)
                var ttl = ExtractTtlFromResponse(response);
                var cacheDuration = TimeSpan.FromSeconds(Math.Min(ttl, 300));
                if (cacheDuration < TimeSpan.FromSeconds(10))
                    cacheDuration = TimeSpan.FromSeconds(60);

                _cache[cacheKey] = new CachedDnsResult
                {
                    ResponseData = response,
                    ExpiresAt = DateTime.UtcNow.Add(cacheDuration),
                    Domain = domain
                };
            }
            else
            {
                Interlocked.Increment(ref _failedQueries);
            }
        }

        private bool IsParentDomainBlocked(string domain)
        {
            var parts = domain.Split('.');
            for (int i = 1; i < parts.Length - 1; i++)
            {
                var parent = string.Join(".", parts[i..]);
                if (_blocklist.ContainsKey(parent)) return true;
                if (_isBlocked?.Invoke(parent) == true) return true;
            }
            return false;
        }

        #endregion

        #region DNS-over-TLS

        private byte[]? ForwardQueryDoT(byte[] query)
        {
            int attempts = 0;
            foreach (var resolver in _dotResolvers)
            {
                if (++attempts > 2) break;
                try
                {
                    using var tcp = new TcpClient();
                    tcp.SendTimeout = 2000;
                    tcp.ReceiveTimeout = 2000;

                    var connectTask = tcp.ConnectAsync(IPAddress.Parse(resolver.Ip), DotPort);
                    if (!connectTask.Wait(2000)) continue;

                    using var sslStream = new SslStream(tcp.GetStream(), false,
                        (sender, cert, chain, errors) =>
                        {
                            if (errors == SslPolicyErrors.None) return true;
                            _context.Log(LogLevel.Warning, ModuleName,
                                $"DoT certificate error for {resolver.Hostname}: {errors}");
                            return false;
                        });

                    var authTask = sslStream.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                    {
                        TargetHost = resolver.Hostname,
                        EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13
                    });
                    if (!authTask.Wait(2000)) continue;

                    // DNS over TLS uses length-prefixed messages
                    var lengthPrefix = new byte[2];
                    lengthPrefix[0] = (byte)(query.Length >> 8);
                    lengthPrefix[1] = (byte)(query.Length & 0xFF);

                    sslStream.Write(lengthPrefix);
                    sslStream.Write(query);
                    sslStream.Flush();

                    // Read response length
                    var respLen = new byte[2];
                    int read = 0;
                    while (read < 2)
                    {
                        int r = sslStream.Read(respLen, read, 2 - read);
                        if (r == 0) break;
                        read += r;
                    }
                    if (read < 2) continue;

                    int responseLength = (respLen[0] << 8) | respLen[1];
                    if (responseLength <= 0 || responseLength > MaxUdpPacketSize) continue;

                    var response = new byte[responseLength];
                    read = 0;
                    while (read < responseLength)
                    {
                        int r = sslStream.Read(response, read, responseLength - read);
                        if (r == 0) break;
                        read += r;
                    }

                    if (read == responseLength)
                        return response;
                }
                catch { }
            }

            _dotAvailable = false;
            return null;
        }

        private DateTime _lastDotTest = DateTime.MinValue;

        private Task TestDotConnectivity()
        {
            // Don't retest more than once every 5 minutes
            if ((DateTime.UtcNow - _lastDotTest).TotalMinutes < 5)
                return Task.CompletedTask;
            _lastDotTest = DateTime.UtcNow;

            try
            {
                var testQuery = BuildTestQuery("cloudflare.com");
                var result = ForwardQueryDoT(testQuery);
                _dotAvailable = result != null;

                _context.Log(LogLevel.Info, ModuleName,
                    _dotAvailable
                        ? "DNS-over-TLS is working. All queries encrypted."
                        : "DNS-over-TLS unavailable. Using UDP fallback.");
            }
            catch
            {
                _dotAvailable = false;
            }
            return Task.CompletedTask;
        }

        #endregion

        #region UDP Forwarding (Fallback)

        private byte[]? ForwardQueryUdp(byte[] query, bool useSecondary = false)
        {
            var primary = useSecondary ? _fallbackUdp2 : _fallbackUdp1;
            var secondary = useSecondary ? _fallbackUdp1 : _fallbackUdp2;

            try
            {
                using var forwarder = new UdpClient();
                forwarder.Client.ReceiveTimeout = 3000;
                forwarder.Send(query, query.Length, primary);
                var remoteEp = new IPEndPoint(IPAddress.Any, 0);
                return forwarder.Receive(ref remoteEp);
            }
            catch
            {
                try
                {
                    using var forwarder = new UdpClient();
                    forwarder.Client.ReceiveTimeout = 1500;
                    forwarder.Send(query, query.Length, secondary);
                    var remoteEp = new IPEndPoint(IPAddress.Any, 0);
                    return forwarder.Receive(ref remoteEp);
                }
                catch { return null; }
            }
        }

        #endregion

        #region Cache Poisoning Detection

        private bool ValidateResponse(byte[] response, string expectedDomain, ushort expectedType)
        {
            try
            {
                if (response.Length < 12) return false;

                // Check RCODE (response code) - 0 = no error, 3 = NXDOMAIN (both valid)
                int rcode = response[3] & 0x0F;
                if (rcode != 0 && rcode != 3) return false;

                // Verify QR bit is set (this IS a response)
                if ((response[2] & 0x80) == 0) return false;

                // Extract domain from question section of response and verify it matches
                var responseDomain = ExtractDomainFromQuery(response);
                if (!string.Equals(responseDomain, expectedDomain, StringComparison.OrdinalIgnoreCase))
                    return false;

                // Check answer count is reasonable
                int ancount = (response[6] << 8) | response[7];
                if (ancount > 50) return false;

                return true;
            }
            catch
            {
                return false;
            }
        }

        private static int ExtractTtlFromResponse(byte[] response)
        {
            try
            {
                if (response.Length < 12) return 60;

                // Skip header (12 bytes) and question section
                int offset = 12;
                // Skip question name
                while (offset < response.Length && response[offset] != 0)
                {
                    if ((response[offset] & 0xC0) == 0xC0) { offset += 2; break; }
                    offset += response[offset] + 1;
                }
                if ((response[offset] & 0xC0) != 0xC0) offset++; // null terminator
                offset += 4; // skip QTYPE and QCLASS

                // Read first answer TTL
                if (offset + 10 >= response.Length) return 60;
                // Skip answer name
                if ((response[offset] & 0xC0) == 0xC0) offset += 2;
                else while (offset < response.Length && response[offset] != 0) offset += response[offset] + 1;

                offset += 4; // TYPE + CLASS
                if (offset + 4 > response.Length) return 60;

                int ttl = (response[offset] << 24) | (response[offset + 1] << 16) |
                          (response[offset + 2] << 8) | response[offset + 3];
                return Math.Max(10, Math.Min(ttl, 86400));
            }
            catch { return 60; }
        }

        #endregion

        #region Anti-Bypass Watchdog

        private async Task DnsWatchdogLoop()
        {
            // Check every 15 seconds if DNS is still pointing to us
            while (!_cts!.Token.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(15000, _cts.Token);
                    CheckDnsSettings();
                    CheckForDnsLeaks();
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    _context.Log(LogLevel.Warning, ModuleName, $"Watchdog error: {ex.Message}");
                }
            }
        }

        private void CheckDnsSettings()
        {
            try
            {
                var interfaces = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces()
                    .Where(n => n.OperationalStatus == System.Net.NetworkInformation.OperationalStatus.Up
                        && n.NetworkInterfaceType != System.Net.NetworkInformation.NetworkInterfaceType.Loopback)
                    .ToList();

                foreach (var nic in interfaces)
                {
                    var ipProps = nic.GetIPProperties();
                    var dnsAddresses = ipProps.DnsAddresses;

                    bool pointsToUs = dnsAddresses.Any(d => IPAddress.IsLoopback(d));

                    if (!pointsToUs && _isActive)
                    {
                        Interlocked.Increment(ref _antiBypassDetections);

                        _context.Log(LogLevel.Warning, ModuleName,
                            $"DNS bypass detected on {nic.Name}! DNS changed to: {string.Join(", ", dnsAddresses)}. Restoring.");

                        _context.RaiseAlert(new Alert
                        {
                            ModuleId = ModuleName,
                            Title = "DNS Protection Bypass Detected",
                            Message = $"DNS settings on {nic.Name} were changed away from PC Plus protection. " +
                                      $"Current DNS: {string.Join(", ", dnsAddresses)}. Settings restored automatically.",
                            Severity = AlertSeverity.Critical,
                            Category = "dns-bypass",
                            Metadata = new()
                            {
                                ["interface"] = nic.Name,
                                ["changed_to"] = string.Join(", ", dnsAddresses.Select(d => d.ToString()))
                            }
                        });

                        // Restore our DNS setting
                        RunNetsh($"interface ip set dns name=\"{nic.Name}\" static 127.0.0.1 primary");
                    }
                }
            }
            catch { }
        }

        private void CheckForDnsLeaks()
        {
            // Check if any process is making DNS queries to external resolvers directly
            // (bypassing our proxy by connecting to port 53 on external IPs)
            try
            {
                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "netstat",
                    Arguments = "-an",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true
                };

                using var proc = System.Diagnostics.Process.Start(psi);
                if (proc == null) return;

                var output = proc.StandardOutput.ReadToEnd();
                proc.WaitForExit(5000);

                foreach (var line in output.Split('\n'))
                {
                    var trimmed = line.Trim();
                    if (!trimmed.Contains(":53 ") && !trimmed.Contains(":53\t")) continue;
                    if (trimmed.Contains("127.0.0.1:53")) continue;
                    if (trimmed.Contains("0.0.0.0:53")) continue;

                    // Someone is talking to an external DNS server directly
                    if (trimmed.Contains("ESTABLISHED") || trimmed.Contains("SYN_SENT"))
                    {
                        Interlocked.Increment(ref _antiBypassDetections);
                        _context.Log(LogLevel.Warning, ModuleName,
                            $"DNS leak detected: {trimmed}");
                    }
                }
            }
            catch { }
        }

        #endregion

        #region Cache Management

        private async Task CacheCleanupLoop()
        {
            while (!_cts!.Token.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(60000, _cts.Token); // Every minute

                    // Remove expired entries
                    var expired = _cache.Where(kv => kv.Value.ExpiresAt < DateTime.UtcNow)
                        .Select(kv => kv.Key).ToList();
                    foreach (var key in expired)
                        _cache.TryRemove(key, out _);

                    // If cache is too large, remove oldest entries
                    if (_cache.Count > MaxCacheEntries)
                    {
                        var toRemove = _cache
                            .OrderBy(kv => kv.Value.ExpiresAt)
                            .Take(CacheCleanupThreshold)
                            .Select(kv => kv.Key).ToList();
                        foreach (var key in toRemove)
                            _cache.TryRemove(key, out _);

                        _context.Log(LogLevel.Info, ModuleName,
                            $"Cache pruned: removed {toRemove.Count} entries, {_cache.Count} remaining");
                    }

                    // Clean old poison attempts
                    var oldAttempts = _poisonAttempts
                        .Where(kv => kv.Value < DateTime.UtcNow.AddHours(-1))
                        .Select(kv => kv.Key).ToList();
                    foreach (var key in oldAttempts)
                        _poisonAttempts.TryRemove(key, out _);

                    if (_dotConfigEnabled && !_dotAvailable)
                        await TestDotConnectivity();
                }
                catch (OperationCanceledException) { break; }
                catch { }
            }
        }

        #endregion

        #region DNS Packet Helpers

        private static string ExtractDomainFromQuery(byte[] packet)
        {
            try
            {
                if (packet.Length < 12) return "";
                int offset = 12;
                var parts = new List<string>();

                while (offset < packet.Length)
                {
                    int labelLen = packet[offset];
                    if (labelLen == 0) break;
                    if ((labelLen & 0xC0) == 0xC0) break; // Compression pointer
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

        private static ushort ExtractQueryType(byte[] packet)
        {
            try
            {
                if (packet.Length < 12) return 0;
                int offset = 12;
                while (offset < packet.Length)
                {
                    int labelLen = packet[offset];
                    if (labelLen == 0) { offset++; break; }
                    if ((labelLen & 0xC0) == 0xC0) { offset += 2; break; }
                    offset += labelLen + 1;
                }
                if (offset + 2 > packet.Length) return 0;
                return (ushort)((packet[offset] << 8) | packet[offset + 1]);
            }
            catch { return 0; }
        }

        private static byte[] BuildBlockedResponse(byte[] query)
        {
            var response = new byte[query.Length + 16];
            Array.Copy(query, response, query.Length);

            response[2] = 0x81; // QR=1, RD=1
            response[3] = 0x80; // RA=1
            response[6] = 0x00;
            response[7] = 0x01; // ANCOUNT = 1

            int answerOffset = query.Length;
            response[answerOffset] = 0xC0;
            response[answerOffset + 1] = 0x0C;
            response[answerOffset + 2] = 0x00; // Type A
            response[answerOffset + 3] = 0x01;
            response[answerOffset + 4] = 0x00; // Class IN
            response[answerOffset + 5] = 0x01;
            response[answerOffset + 6] = 0x00; // TTL = 60s
            response[answerOffset + 7] = 0x00;
            response[answerOffset + 8] = 0x00;
            response[answerOffset + 9] = 0x3C;
            response[answerOffset + 10] = 0x00; // RDLENGTH = 4
            response[answerOffset + 11] = 0x04;
            response[answerOffset + 12] = 0x00; // 0.0.0.0
            response[answerOffset + 13] = 0x00;
            response[answerOffset + 14] = 0x00;
            response[answerOffset + 15] = 0x00;

            return response[..(answerOffset + 16)];
        }

        private static byte[] BuildCachedResponse(byte[] originalQuery, byte[] cachedResponse)
        {
            var response = (byte[])cachedResponse.Clone();
            response[0] = originalQuery[0];
            response[1] = originalQuery[1];
            return response;
        }

        private static byte[] BuildTestQuery(string domain)
        {
            var parts = domain.Split('.');
            var packet = new List<byte>();

            // Header
            packet.AddRange(new byte[] { 0xAB, 0xCD }); // Transaction ID
            packet.AddRange(new byte[] { 0x01, 0x00 }); // Standard query, RD=1
            packet.AddRange(new byte[] { 0x00, 0x01 }); // QDCOUNT = 1
            packet.AddRange(new byte[] { 0x00, 0x00 }); // ANCOUNT
            packet.AddRange(new byte[] { 0x00, 0x00 }); // NSCOUNT
            packet.AddRange(new byte[] { 0x00, 0x00 }); // ARCOUNT

            // Question
            foreach (var part in parts)
            {
                packet.Add((byte)part.Length);
                packet.AddRange(System.Text.Encoding.ASCII.GetBytes(part));
            }
            packet.Add(0); // End of name

            packet.AddRange(new byte[] { 0x00, 0x01 }); // Type A
            packet.AddRange(new byte[] { 0x00, 0x01 }); // Class IN

            return packet.ToArray();
        }

        #endregion

        #region Blocklist Management

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

        #endregion

        #region Network Interface Management

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
                var interfaces = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces()
                    .Where(n => n.OperationalStatus == System.Net.NetworkInformation.OperationalStatus.Up
                        && n.NetworkInterfaceType != System.Net.NetworkInformation.NetworkInterfaceType.Loopback)
                    .ToList();

                foreach (var nic in interfaces)
                {
                    RunNetsh($"interface ip set dns name=\"{nic.Name}\" static 127.0.0.1 primary");
                    _context.Log(LogLevel.Info, ModuleName, $"Set DNS to 127.0.0.1 on interface: {nic.Name}");
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
                    RunNetsh($"interface ip set dns name=\"{nic.Name}\" dhcp");

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

        #endregion
    }

    internal class CachedDnsResult
    {
        public byte[] ResponseData { get; set; } = Array.Empty<byte>();
        public DateTime ExpiresAt { get; set; }
        public string Domain { get; set; } = "";
    }

    internal record DotResolver(string Ip, string Hostname);

    public class DnsProxyStats
    {
        public long TotalQueries { get; set; }
        public long BlockedQueries { get; set; }
        public long CachedResponses { get; set; }
        public long DotQueries { get; set; }
        public long UdpFallbackQueries { get; set; }
        public long FailedQueries { get; set; }
        public long AntiBypassDetections { get; set; }
        public long CachePoisonAttempts { get; set; }
        public int CacheSize { get; set; }
        public int BlocklistSize { get; set; }
        public bool DotAvailable { get; set; }
        public bool IsActive { get; set; }
    }
}
