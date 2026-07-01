using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.RegularExpressions;
using PCPlus.Core.Interfaces;
using PCPlus.Core.Models;

namespace PCPlus.Service.Modules.NetworkSecurity
{
    public class NetworkSecurityModule : IModule
    {
        public string Id => "network-security";
        public string Name => "Network Security Monitor";
        public string Version => "1.0.0";
        public LicenseTier RequiredTier => LicenseTier.Free;
        public bool IsRunning { get; private set; }

        private IModuleContext _context = null!;
        private Timer? _eventCollector;
        private Timer? _networkScanner;
        private Timer? _bruteForceChecker;
        private Timer? _dataPersister;

        private readonly object _dataLock = new();
        private readonly List<LoginEvent> _loginEvents = new();
        private readonly List<NetworkDevice> _discoveredDevices = new();
        private readonly List<PortScanAlert> _portScanAlerts = new();
        private readonly List<BruteForceAlert> _bruteForceAlerts = new();
        private readonly Dictionary<string, LoginAttemptTracker> _loginTrackers = new();
        private readonly Dictionary<string, ConnectionTracker> _connectionTrackers = new();
        private readonly HashSet<string> _blockedIps = new();

        private DateTime _lastEventTime = DateTime.UtcNow.AddHours(-1);
        private DateTime _moduleStartTime;
        private NetworkSecurityStats _stats = new();
        private OperationMode _mode = OperationMode.Passive;

        private static readonly string DataDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "PCPlusEndpoint", "NetworkSecurity");

        private static readonly string EventsPath = Path.Combine(DataDir, "login_events.json");
        private static readonly string DevicesPath = Path.Combine(DataDir, "discovered_devices.json");
        private static readonly string AlertsPath = Path.Combine(DataDir, "alerts.json");
        private static readonly string StatsPath = Path.Combine(DataDir, "stats.json");
        private static readonly string BlockedPath = Path.Combine(DataDir, "blocked_ips.json");

        private const int BRUTE_FORCE_THRESHOLD = 5;
        private const int BRUTE_FORCE_WINDOW_MINUTES = 10;
        private const int PORT_SCAN_THRESHOLD = 15;
        private const int PORT_SCAN_WINDOW_SECONDS = 60;
        private const int MAX_STORED_EVENTS = 10000;
        private const int MAX_STORED_ALERTS = 1000;

        public Task InitializeAsync(IModuleContext context)
        {
            _context = context;
            Directory.CreateDirectory(DataDir);
            LoadPersistedData();
            return Task.CompletedTask;
        }

        public Task StartAsync(CancellationToken cancellationToken)
        {
            IsRunning = true;
            _moduleStartTime = DateTime.UtcNow;

            var modeStr = _context.Config.GetValue("networkSecurityMode");
            if (!string.IsNullOrEmpty(modeStr) && Enum.TryParse<OperationMode>(modeStr, true, out var mode))
                _mode = mode;

            _context.Log(LogLevel.Info, Id, $"Starting in {_mode} mode");

            _eventCollector = new Timer(_ => CollectWindowsSecurityEvents(), null,
                TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(30));

            _bruteForceChecker = new Timer(_ => CheckBruteForcePatterns(), null,
                TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(15));

            _networkScanner = new Timer(_ => ScanLocalNetwork(), null,
                TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(15));

            _dataPersister = new Timer(_ => PersistData(), null,
                TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(5));

            _context.Log(LogLevel.Info, Id, "Network Security Monitor started");
            return Task.CompletedTask;
        }

        public Task StopAsync()
        {
            _eventCollector?.Dispose();
            _networkScanner?.Dispose();
            _bruteForceChecker?.Dispose();
            _dataPersister?.Dispose();
            PersistData();
            IsRunning = false;
            return Task.CompletedTask;
        }

        public Task<ModuleResponse> HandleCommandAsync(ModuleCommand command)
        {
            return command.Action switch
            {
                "GetNetworkSecurityStatus" or "GetStatus" => Task.FromResult(GetStatusResponse()),
                "GetLoginEvents" => Task.FromResult(GetLoginEventsResponse(command)),
                "GetBruteForceAlerts" => Task.FromResult(GetBruteForceAlertsResponse()),
                "GetDiscoveredDevices" => Task.FromResult(GetDevicesResponse()),
                "GetPortScanAlerts" => Task.FromResult(GetPortScanAlertsResponse()),
                "GetNetworkReport" => Task.FromResult(GetFullReportResponse()),
                "SetMode" => HandleSetMode(command),
                "BlockIP" => HandleBlockIP(command),
                "UnblockIP" => HandleUnblockIP(command),
                "ScanNow" => HandleScanNow(),
                "event" => Task.FromResult(ModuleResponse.Ok()),
                _ => Task.FromResult(ModuleResponse.Fail($"Unknown: {command.Action}"))
            };
        }

        public ModuleStatus GetStatus()
        {
            lock (_dataLock)
            {
                return new ModuleStatus
                {
                    ModuleId = Id,
                    ModuleName = Name,
                    IsRunning = IsRunning,
                    RequiredTier = RequiredTier,
                    StatusText = $"Mode: {_mode} | {_stats.TotalEventsCollected} events | {_bruteForceAlerts.Count} alerts",
                    LastActivity = _stats.LastCollectionTime,
                    Metrics = new()
                    {
                        ["mode"] = _mode.ToString(),
                        ["totalEvents"] = _stats.TotalEventsCollected,
                        ["failedLogins"] = _stats.FailedLoginCount,
                        ["successfulLogins"] = _stats.SuccessfulLoginCount,
                        ["bruteForceAlerts"] = _bruteForceAlerts.Count,
                        ["portScanAlerts"] = _portScanAlerts.Count,
                        ["discoveredDevices"] = _discoveredDevices.Count,
                        ["blockedIps"] = _blockedIps.Count
                    }
                };
            }
        }

        #region Windows Event Log Collection

        private void CollectWindowsSecurityEvents()
        {
            try
            {
                CollectSecurityLogEvents();
                CollectOpenSshEvents();
                DetectPortScans();
            }
            catch (Exception ex)
            {
                _context.Log(LogLevel.Warning, Id, $"Event collection error: {ex.Message}");
            }
        }

        private void CollectSecurityLogEvents()
        {
            try
            {
                var query = new EventLogQuery("Security", PathType.LogName,
                    $"*[System[(EventID=4624 or EventID=4625 or EventID=4740 or EventID=4723 or EventID=4724 or EventID=4720 or EventID=4726 or EventID=4732 or EventID=4733 or EventID=4648 or EventID=4672) and TimeCreated[@SystemTime>='{_lastEventTime:yyyy-MM-ddTHH:mm:ss.000Z}']]]");

                using var reader = new EventLogReader(query);
                var newEvents = new List<LoginEvent>();
                EventRecord? record;

                while ((record = reader.ReadEvent()) != null)
                {
                    using (record)
                    {
                        try
                        {
                            var evt = ParseSecurityEvent(record);
                            if (evt != null)
                                newEvents.Add(evt);
                        }
                        catch { }
                    }
                }

                if (newEvents.Count > 0)
                {
                    lock (_dataLock)
                    {
                        _loginEvents.AddRange(newEvents);
                        while (_loginEvents.Count > MAX_STORED_EVENTS)
                            _loginEvents.RemoveAt(0);

                        _stats.TotalEventsCollected += newEvents.Count;
                        _stats.FailedLoginCount += newEvents.Count(e => e.EventType == LoginEventType.FailedLogin);
                        _stats.SuccessfulLoginCount += newEvents.Count(e => e.EventType == LoginEventType.SuccessfulLogin);
                        _stats.LastCollectionTime = DateTime.UtcNow;

                        foreach (var evt in newEvents.Where(e =>
                            e.EventType == LoginEventType.FailedLogin && !string.IsNullOrEmpty(e.SourceIP)))
                        {
                            TrackLoginAttempt(evt);
                        }
                    }

                    _lastEventTime = newEvents.Max(e => e.Timestamp).AddSeconds(1);
                }
            }
            catch (UnauthorizedAccessException)
            {
                _context.Log(LogLevel.Warning, Id, "Access denied to Security event log - requires admin privileges");
            }
            catch (Exception ex)
            {
                _context.Log(LogLevel.Warning, Id, $"Security log collection error: {ex.Message}");
            }
        }

        private LoginEvent? ParseSecurityEvent(EventRecord record)
        {
            var eventId = record.Id;
            var timeCreated = record.TimeCreated ?? DateTime.UtcNow;
            var xml = record.ToXml();

            return eventId switch
            {
                4624 => ParseLogonEvent(xml, timeCreated, true),
                4625 => ParseLogonEvent(xml, timeCreated, false),
                4740 => ParseAccountLockout(xml, timeCreated),
                4723 or 4724 => ParsePasswordChange(xml, timeCreated, eventId),
                4720 => ParseAccountCreated(xml, timeCreated),
                4726 => ParseAccountDeleted(xml, timeCreated),
                4732 => ParseGroupMemberAdded(xml, timeCreated),
                4733 => ParseGroupMemberRemoved(xml, timeCreated),
                4648 => ParseExplicitLogon(xml, timeCreated),
                4672 => ParseSpecialPrivileges(xml, timeCreated),
                _ => null
            };
        }

        private LoginEvent? ParseLogonEvent(string xml, DateTime timestamp, bool success)
        {
            var logonType = ExtractXmlValue(xml, "LogonType");
            var logonTypeInt = int.TryParse(logonType, out var lt) ? lt : 0;

            // Skip service/batch/system logons (types 0, 5) to reduce noise
            if (logonTypeInt == 0 || logonTypeInt == 5) return null;

            var targetUser = ExtractXmlValue(xml, "TargetUserName");
            var targetDomain = ExtractXmlValue(xml, "TargetDomainName");
            var sourceIp = ExtractXmlValue(xml, "IpAddress");
            var sourcePort = ExtractXmlValue(xml, "IpPort");
            var processName = ExtractXmlValue(xml, "ProcessName");
            var status = ExtractXmlValue(xml, "Status");
            var subStatus = ExtractXmlValue(xml, "SubStatus");
            var workstation = ExtractXmlValue(xml, "WorkstationName");

            // Skip local system accounts
            if (targetUser == "-" || targetUser == "SYSTEM" || targetUser == "LOCAL SERVICE" ||
                targetUser == "NETWORK SERVICE" || targetUser == "ANONYMOUS LOGON" ||
                targetUser?.EndsWith("$") == true)
                return null;

            // Clean up source IP
            if (sourceIp == "-" || sourceIp == "::1" || sourceIp == "127.0.0.1") sourceIp = "Local";

            var logonTypeName = logonTypeInt switch
            {
                2 => "Interactive",
                3 => "Network",
                4 => "Batch",
                7 => "Unlock",
                8 => "NetworkCleartext",
                10 => "RemoteInteractive (RDP)",
                11 => "CachedInteractive",
                _ => $"Type {logonTypeInt}"
            };

            var failReason = "";
            if (!success)
            {
                failReason = (status, subStatus) switch
                {
                    ("0xC000006D", _) => "Bad username or password",
                    ("0xC000006A", _) => "Incorrect password",
                    ("0xC0000064", _) => "User does not exist",
                    ("0xC0000234", _) => "Account locked out",
                    ("0xC0000072", _) => "Account disabled",
                    ("0xC000006F", _) => "Outside authorized hours",
                    ("0xC0000070", _) => "Unauthorized workstation",
                    ("0xC0000071", _) => "Password expired",
                    ("0xC000015B", _) => "Logon type not granted",
                    ("0xC0000193", _) => "Account expired",
                    ("0xC0000413", _) => "Authentication firewall",
                    _ => $"Status: {status}/{subStatus}"
                };
            }

            return new LoginEvent
            {
                EventId = success ? 4624 : 4625,
                EventType = success ? LoginEventType.SuccessfulLogin : LoginEventType.FailedLogin,
                Timestamp = timestamp,
                Username = string.IsNullOrEmpty(targetDomain) || targetDomain == "-"
                    ? targetUser ?? ""
                    : $"{targetDomain}\\{targetUser}",
                SourceIP = sourceIp ?? "",
                SourcePort = int.TryParse(sourcePort, out var sp) ? sp : 0,
                LogonType = logonTypeName,
                LogonTypeId = logonTypeInt,
                ProcessName = processName ?? "",
                WorkstationName = workstation ?? "",
                FailureReason = failReason,
                Protocol = logonTypeInt == 10 ? "RDP" : logonTypeInt == 3 ? "SMB/Network" : "Local"
            };
        }

        private LoginEvent ParseAccountLockout(string xml, DateTime timestamp) => new()
        {
            EventId = 4740,
            EventType = LoginEventType.AccountLockout,
            Timestamp = timestamp,
            Username = ExtractXmlValue(xml, "TargetUserName") ?? "",
            SourceIP = ExtractXmlValue(xml, "TargetDomainName") ?? "",
            LogonType = "Account Lockout",
            Protocol = "Windows"
        };

        private LoginEvent ParsePasswordChange(string xml, DateTime timestamp, int eventId) => new()
        {
            EventId = eventId,
            EventType = LoginEventType.PasswordChange,
            Timestamp = timestamp,
            Username = ExtractXmlValue(xml, "TargetUserName") ?? "",
            SourceIP = "Local",
            LogonType = eventId == 4723 ? "Password Change (self)" : "Password Reset (admin)",
            Protocol = "Windows"
        };

        private LoginEvent ParseAccountCreated(string xml, DateTime timestamp) => new()
        {
            EventId = 4720,
            EventType = LoginEventType.AccountCreated,
            Timestamp = timestamp,
            Username = ExtractXmlValue(xml, "TargetUserName") ?? "",
            SourceIP = "Local",
            LogonType = "Account Created",
            Protocol = "Windows",
            Detail = $"Created by: {ExtractXmlValue(xml, "SubjectUserName")}"
        };

        private LoginEvent ParseAccountDeleted(string xml, DateTime timestamp) => new()
        {
            EventId = 4726,
            EventType = LoginEventType.AccountDeleted,
            Timestamp = timestamp,
            Username = ExtractXmlValue(xml, "TargetUserName") ?? "",
            SourceIP = "Local",
            LogonType = "Account Deleted",
            Protocol = "Windows",
            Detail = $"Deleted by: {ExtractXmlValue(xml, "SubjectUserName")}"
        };

        private LoginEvent ParseGroupMemberAdded(string xml, DateTime timestamp) => new()
        {
            EventId = 4732,
            EventType = LoginEventType.GroupChange,
            Timestamp = timestamp,
            Username = ExtractXmlValue(xml, "MemberName") ?? "",
            SourceIP = "Local",
            LogonType = "Group Member Added",
            Protocol = "Windows",
            Detail = $"Added to group: {ExtractXmlValue(xml, "TargetUserName")} by {ExtractXmlValue(xml, "SubjectUserName")}"
        };

        private LoginEvent ParseGroupMemberRemoved(string xml, DateTime timestamp) => new()
        {
            EventId = 4733,
            EventType = LoginEventType.GroupChange,
            Timestamp = timestamp,
            Username = ExtractXmlValue(xml, "MemberName") ?? "",
            SourceIP = "Local",
            LogonType = "Group Member Removed",
            Protocol = "Windows",
            Detail = $"Removed from group: {ExtractXmlValue(xml, "TargetUserName")} by {ExtractXmlValue(xml, "SubjectUserName")}"
        };

        private LoginEvent? ParseExplicitLogon(string xml, DateTime timestamp)
        {
            var targetUser = ExtractXmlValue(xml, "TargetUserName");
            var targetServer = ExtractXmlValue(xml, "TargetServerName");
            if (targetUser == "-" || targetUser?.EndsWith("$") == true) return null;

            return new LoginEvent
            {
                EventId = 4648,
                EventType = LoginEventType.ExplicitCredentials,
                Timestamp = timestamp,
                Username = targetUser ?? "",
                SourceIP = "Local",
                LogonType = "Explicit Credentials (RunAs)",
                Protocol = "Windows",
                Detail = $"Target server: {targetServer}"
            };
        }

        private LoginEvent? ParseSpecialPrivileges(string xml, DateTime timestamp)
        {
            var user = ExtractXmlValue(xml, "SubjectUserName");
            if (user == "SYSTEM" || user == "-" || user?.EndsWith("$") == true) return null;

            return new LoginEvent
            {
                EventId = 4672,
                EventType = LoginEventType.PrivilegeEscalation,
                Timestamp = timestamp,
                Username = user ?? "",
                SourceIP = "Local",
                LogonType = "Special Privileges Assigned",
                Protocol = "Windows"
            };
        }

        private void CollectOpenSshEvents()
        {
            try
            {
                var query = new EventLogQuery("OpenSSH/Operational", PathType.LogName,
                    $"*[System[TimeCreated[@SystemTime>='{_lastEventTime:yyyy-MM-ddTHH:mm:ss.000Z}']]]");

                using var reader = new EventLogReader(query);
                EventRecord? record;

                while ((record = reader.ReadEvent()) != null)
                {
                    using (record)
                    {
                        try
                        {
                            var message = record.FormatDescription() ?? "";
                            var timestamp = record.TimeCreated ?? DateTime.UtcNow;

                            LoginEvent? evt = null;

                            if (message.Contains("Accepted") || message.Contains("authenticated"))
                            {
                                var ip = ExtractIpFromMessage(message);
                                var user = ExtractUserFromSshMessage(message);
                                evt = new LoginEvent
                                {
                                    EventId = record.Id,
                                    EventType = LoginEventType.SuccessfulLogin,
                                    Timestamp = timestamp,
                                    Username = user,
                                    SourceIP = ip,
                                    LogonType = "SSH",
                                    Protocol = "SSH"
                                };
                            }
                            else if (message.Contains("Failed") || message.Contains("Invalid user") || message.Contains("refused"))
                            {
                                var ip = ExtractIpFromMessage(message);
                                var user = ExtractUserFromSshMessage(message);
                                evt = new LoginEvent
                                {
                                    EventId = record.Id,
                                    EventType = LoginEventType.FailedLogin,
                                    Timestamp = timestamp,
                                    Username = user,
                                    SourceIP = ip,
                                    LogonType = "SSH",
                                    Protocol = "SSH",
                                    FailureReason = message.Contains("Invalid user") ? "Invalid user" : "Authentication failed"
                                };
                            }

                            if (evt != null)
                            {
                                lock (_dataLock)
                                {
                                    _loginEvents.Add(evt);
                                    _stats.TotalEventsCollected++;
                                    if (evt.EventType == LoginEventType.FailedLogin)
                                    {
                                        _stats.FailedLoginCount++;
                                        if (!string.IsNullOrEmpty(evt.SourceIP))
                                            TrackLoginAttempt(evt);
                                    }
                                    else
                                        _stats.SuccessfulLoginCount++;
                                }
                            }
                        }
                        catch { }
                    }
                }
            }
            catch (EventLogNotFoundException)
            {
                // OpenSSH not installed - that's fine
            }
            catch (Exception ex)
            {
                _context.Log(LogLevel.Debug, Id, $"OpenSSH log check: {ex.Message}");
            }
        }

        #endregion

        #region Brute Force Detection

        private void TrackLoginAttempt(LoginEvent evt)
        {
            var key = $"{evt.SourceIP}|{evt.Protocol}";
            if (!_loginTrackers.TryGetValue(key, out var tracker))
            {
                tracker = new LoginAttemptTracker { IP = evt.SourceIP, Protocol = evt.Protocol };
                _loginTrackers[key] = tracker;
            }

            tracker.Attempts.Add(new AttemptRecord
            {
                Timestamp = evt.Timestamp,
                Username = evt.Username,
                Success = evt.EventType == LoginEventType.SuccessfulLogin
            });

            // Keep only recent attempts
            var cutoff = DateTime.UtcNow.AddMinutes(-BRUTE_FORCE_WINDOW_MINUTES * 3);
            tracker.Attempts.RemoveAll(a => a.Timestamp < cutoff);
        }

        private void CheckBruteForcePatterns()
        {
            try
            {
                var windowStart = DateTime.UtcNow.AddMinutes(-BRUTE_FORCE_WINDOW_MINUTES);

                lock (_dataLock)
                {
                    foreach (var (key, tracker) in _loginTrackers)
                    {
                        var recentFails = tracker.Attempts
                            .Where(a => a.Timestamp >= windowStart && !a.Success)
                            .ToList();

                        if (recentFails.Count < BRUTE_FORCE_THRESHOLD) continue;

                        // Check if we already have a recent alert for this IP
                        var existingAlert = _bruteForceAlerts
                            .LastOrDefault(a => a.SourceIP == tracker.IP && a.Protocol == tracker.Protocol);

                        if (existingAlert != null &&
                            (DateTime.UtcNow - existingAlert.LastAttempt).TotalMinutes < BRUTE_FORCE_WINDOW_MINUTES)
                        {
                            existingAlert.AttemptCount = recentFails.Count;
                            existingAlert.LastAttempt = recentFails.Max(a => a.Timestamp);
                            existingAlert.TargetAccounts = recentFails.Select(a => a.Username).Distinct().ToList();
                            continue;
                        }

                        var alert = new BruteForceAlert
                        {
                            SourceIP = tracker.IP,
                            Protocol = tracker.Protocol,
                            AttemptCount = recentFails.Count,
                            FirstAttempt = recentFails.Min(a => a.Timestamp),
                            LastAttempt = recentFails.Max(a => a.Timestamp),
                            TargetAccounts = recentFails.Select(a => a.Username).Distinct().ToList(),
                            IsBlocked = _blockedIps.Contains(tracker.IP)
                        };

                        _bruteForceAlerts.Add(alert);
                        while (_bruteForceAlerts.Count > MAX_STORED_ALERTS)
                            _bruteForceAlerts.RemoveAt(0);

                        _stats.BruteForceAlertsRaised++;

                        // Raise alert to the platform
                        var severity = recentFails.Count >= 20 ? AlertSeverity.Critical :
                                      recentFails.Count >= 10 ? AlertSeverity.Warning :
                                      AlertSeverity.Info;

                        var followedBySuccess = tracker.Attempts
                            .Any(a => a.Success && a.Timestamp > recentFails.Min(f => f.Timestamp));

                        if (followedBySuccess)
                            severity = AlertSeverity.Critical;

                        _context.RaiseAlert(new Alert
                        {
                            ModuleId = Id,
                            Title = followedBySuccess
                                ? $"COMPROMISED: {tracker.Protocol} brute force succeeded from {tracker.IP}"
                                : $"Brute Force: {recentFails.Count} failed {tracker.Protocol} attempts from {tracker.IP}",
                            Message = $"{recentFails.Count} failed login attempts in {BRUTE_FORCE_WINDOW_MINUTES} min. " +
                                     $"Targets: {string.Join(", ", alert.TargetAccounts.Take(5))}" +
                                     (followedBySuccess ? " WARNING: A successful login followed!" : ""),
                            Severity = severity,
                            Category = "network-security",
                            Metadata = new()
                            {
                                ["sourceIp"] = tracker.IP,
                                ["protocol"] = tracker.Protocol,
                                ["attemptCount"] = recentFails.Count.ToString(),
                                ["followedBySuccess"] = followedBySuccess.ToString()
                            }
                        });

                        if (_mode == OperationMode.Active && recentFails.Count >= 10 && !_blockedIps.Contains(tracker.IP))
                        {
                            BlockIpViaFirewall(tracker.IP);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _context.Log(LogLevel.Warning, Id, $"Brute force check error: {ex.Message}");
            }
        }

        #endregion

        #region Port Scan Detection

        private void DetectPortScans()
        {
            try
            {
                var output = RunCommand("netstat", "-an");
                if (string.IsNullOrEmpty(output)) return;

                var now = DateTime.UtcNow;
                var connections = new Dictionary<string, int>();

                foreach (var line in output.Split('\n'))
                {
                    if (!line.Contains("SYN_RECEIVED") && !line.Contains("TIME_WAIT")) continue;

                    var parts = line.Trim().Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length < 3) continue;

                    var foreignAddr = parts[2];
                    var colonIdx = foreignAddr.LastIndexOf(':');
                    if (colonIdx <= 0) continue;

                    var ip = foreignAddr[..colonIdx];
                    if (ip == "0.0.0.0" || ip == "127.0.0.1" || ip == "[::]" || ip == "::1") continue;

                    connections.TryGetValue(ip, out var count);
                    connections[ip] = count + 1;
                }

                foreach (var (ip, count) in connections)
                {
                    if (!_connectionTrackers.TryGetValue(ip, out var tracker))
                    {
                        tracker = new ConnectionTracker { IP = ip };
                        _connectionTrackers[ip] = tracker;
                    }

                    tracker.RecentConnections.Add(new ConnectionRecord { Timestamp = now, Count = count });
                    tracker.RecentConnections.RemoveAll(c => c.Timestamp < now.AddSeconds(-PORT_SCAN_WINDOW_SECONDS * 3));

                    var recentTotal = tracker.RecentConnections
                        .Where(c => c.Timestamp >= now.AddSeconds(-PORT_SCAN_WINDOW_SECONDS))
                        .Sum(c => c.Count);

                    if (recentTotal >= PORT_SCAN_THRESHOLD)
                    {
                        var existing = _portScanAlerts.LastOrDefault(a => a.SourceIP == ip);
                        if (existing != null && (now - existing.DetectedAt).TotalMinutes < 5) continue;

                        var alert = new PortScanAlert
                        {
                            SourceIP = ip,
                            ConnectionCount = recentTotal,
                            DetectedAt = now
                        };

                        lock (_dataLock)
                        {
                            _portScanAlerts.Add(alert);
                            while (_portScanAlerts.Count > MAX_STORED_ALERTS)
                                _portScanAlerts.RemoveAt(0);
                            _stats.PortScanAlertsRaised++;
                        }

                        _context.RaiseAlert(new Alert
                        {
                            ModuleId = Id,
                            Title = $"Port Scan: {recentTotal} connections from {ip}",
                            Message = $"Possible port scan detected - {recentTotal} connection attempts from {ip} in {PORT_SCAN_WINDOW_SECONDS}s",
                            Severity = AlertSeverity.Warning,
                            Category = "network-security"
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                _context.Log(LogLevel.Debug, Id, $"Port scan detection error: {ex.Message}");
            }
        }

        #endregion

        #region Network Device Discovery

        private void ScanLocalNetwork()
        {
            try
            {
                var localAddresses = GetLocalNetworkAddresses();
                if (localAddresses.Count == 0) return;

                var arpOutput = RunCommand("arp", "-a");
                if (string.IsNullOrEmpty(arpOutput)) return;

                var newDevices = new List<NetworkDevice>();
                var arpRegex = new Regex(@"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]+)\s+(\w+)", RegexOptions.Compiled);

                foreach (Match match in arpRegex.Matches(arpOutput))
                {
                    var ip = match.Groups[1].Value;
                    var mac = match.Groups[2].Value.Replace('-', ':').ToUpper();
                    var type = match.Groups[3].Value;

                    if (mac == "FF-FF-FF-FF-FF-FF" || mac == "FF:FF:FF:FF:FF:FF") continue;
                    if (ip.EndsWith(".255") || ip.EndsWith(".0")) continue;

                    var device = new NetworkDevice
                    {
                        IPAddress = ip,
                        MACAddress = mac,
                        Type = type,
                        FirstSeen = DateTime.UtcNow,
                        LastSeen = DateTime.UtcNow,
                        Vendor = ResolveMacVendor(mac)
                    };

                    // Try hostname resolution
                    try
                    {
                        var entry = Dns.GetHostEntry(ip);
                        device.Hostname = entry.HostName;
                    }
                    catch { }

                    newDevices.Add(device);
                }

                lock (_dataLock)
                {
                    foreach (var device in newDevices)
                    {
                        var existing = _discoveredDevices.FirstOrDefault(d => d.MACAddress == device.MACAddress);
                        if (existing != null)
                        {
                            existing.IPAddress = device.IPAddress;
                            existing.LastSeen = DateTime.UtcNow;
                            if (!string.IsNullOrEmpty(device.Hostname))
                                existing.Hostname = device.Hostname;
                        }
                        else
                        {
                            _discoveredDevices.Add(device);
                            _stats.NewDevicesFound++;

                            if (_moduleStartTime < DateTime.UtcNow.AddMinutes(-5))
                            {
                                _context.RaiseAlert(new Alert
                                {
                                    ModuleId = Id,
                                    Title = $"New Device: {device.IPAddress}",
                                    Message = $"New device detected on network: {device.IPAddress} ({device.MACAddress}) {device.Hostname ?? ""} - Vendor: {device.Vendor ?? "Unknown"}",
                                    Severity = AlertSeverity.Info,
                                    Category = "network-security"
                                });
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _context.Log(LogLevel.Debug, Id, $"Network scan error: {ex.Message}");
            }
        }

        private List<IPAddress> GetLocalNetworkAddresses()
        {
            var addresses = new List<IPAddress>();
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up) continue;
                if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;

                foreach (var addr in ni.GetIPProperties().UnicastAddresses)
                {
                    if (addr.Address.AddressFamily == AddressFamily.InterNetwork)
                        addresses.Add(addr.Address);
                }
            }
            return addresses;
        }

        private static string? ResolveMacVendor(string mac)
        {
            var prefix = mac.Replace(":", "").Replace("-", "")[..6].ToUpper();
            return KnownVendors.TryGetValue(prefix, out var vendor) ? vendor : null;
        }

        private static readonly Dictionary<string, string> KnownVendors = new()
        {
            ["D8BBC1"] = "Dell", ["001DD8"] = "Microsoft", ["005056"] = "VMware",
            ["000C29"] = "VMware", ["00155D"] = "Microsoft Hyper-V", ["001C42"] = "Parallels",
            ["0050F2"] = "Microsoft", ["14B31F"] = "Dell", ["F8B156"] = "Dell",
            ["B083FE"] = "Dell", ["A4BB6D"] = "Dell", ["4CCC6A"] = "Dell",
            ["AABBCC"] = "HP", ["001635"] = "HP", ["3C4A92"] = "HP",
            ["18A905"] = "HP", ["94B866"] = "HP", ["80E82C"] = "HP",
            ["3CA82A"] = "Intel", ["A0369F"] = "Intel", ["A4C494"] = "Intel",
            ["DC536C"] = "Intel", ["ECEBB8"] = "Intel", ["485B39"] = "Intel",
            ["AC220B"] = "ASUSTek", ["60455E"] = "Apple", ["A860B6"] = "Apple",
            ["DC2B2A"] = "Apple", ["3C22FB"] = "Apple", ["F0B429"] = "Apple",
            ["A4CF12"] = "Cisco", ["001921"] = "Cisco", ["000C85"] = "Cisco",
            ["000FE2"] = "Cisco", ["001BD4"] = "Cisco", ["0024C4"] = "Cisco",
            ["001122"] = "Synology", ["0011A3"] = "Synology",
            ["EC086B"] = "TP-Link", ["50C7BF"] = "TP-Link", ["60A4B7"] = "TP-Link",
            ["B0BE76"] = "TP-Link", ["1062E5"] = "TP-Link",
            ["001E58"] = "D-Link", ["28107B"] = "D-Link", ["1CBDB9"] = "D-Link",
            ["FCF528"] = "ZyXEL", ["D4F5EF"] = "ZyXEL",
            ["001217"] = "Cisco-Linksys", ["00256B"] = "Netgear",
            ["E091F5"] = "Netgear", ["B07FB9"] = "Netgear",
            ["001E65"] = "Intel PRO", ["0016EA"] = "Intel",
            ["34298F"] = "Lenovo", ["5CF7E6"] = "Lenovo",
            ["001CBF"] = "QNAP", ["24A2E1"] = "QNAP",
            ["88366C"] = "EFI", ["006B9E"] = "Vizio",
            ["74E5F9"] = "Liteon", ["305A3A"] = "ASUSTek",
            ["001A7D"] = "Cyber-Rain", ["001320"] = "Intel",
            ["0025B3"] = "Hewlett Packard", ["2C44FD"] = "Hewlett Packard",
            ["000BCD"] = "Hewlett Packard", ["78E3B5"] = "Hewlett Packard",
            ["30B49E"] = "TP-Link", ["C0C9E3"] = "TP-Link",
            ["002275"] = "Western Digital", ["001F4B"] = "Yamaha"
        };

        #endregion

        #region IP Blocking

        private Task<ModuleResponse> HandleBlockIP(ModuleCommand command)
        {
            var ip = command.Parameters?.GetValueOrDefault("ip") ?? "";
            if (string.IsNullOrEmpty(ip))
                return Task.FromResult(ModuleResponse.Fail("IP address required"));

            lock (_dataLock)
            {
                _blockedIps.Add(ip);
                foreach (var alert in _bruteForceAlerts.Where(a => a.SourceIP == ip))
                    alert.IsBlocked = true;
            }

            if (_mode == OperationMode.Active)
                BlockIpViaFirewall(ip);

            _context.Log(LogLevel.Info, Id, $"IP blocked: {ip}");
            return Task.FromResult(ModuleResponse.Ok($"IP {ip} blocked"));
        }

        private Task<ModuleResponse> HandleUnblockIP(ModuleCommand command)
        {
            var ip = command.Parameters?.GetValueOrDefault("ip") ?? "";
            if (string.IsNullOrEmpty(ip))
                return Task.FromResult(ModuleResponse.Fail("IP address required"));

            lock (_dataLock)
            {
                _blockedIps.Remove(ip);
                foreach (var alert in _bruteForceAlerts.Where(a => a.SourceIP == ip))
                    alert.IsBlocked = false;
            }

            if (_mode == OperationMode.Active)
                UnblockIpFromFirewall(ip);

            _context.Log(LogLevel.Info, Id, $"IP unblocked: {ip}");
            return Task.FromResult(ModuleResponse.Ok($"IP {ip} unblocked"));
        }

        private void BlockIpViaFirewall(string ip)
        {
            try
            {
                RunCommand("netsh", $"advfirewall firewall add rule name=\"PCPlus Block {ip}\" dir=in action=block remoteip={ip}");
                _context.Log(LogLevel.Info, Id, $"Firewall rule added: block {ip}");
                lock (_dataLock) _blockedIps.Add(ip);
            }
            catch (Exception ex)
            {
                _context.Log(LogLevel.Warning, Id, $"Failed to block {ip} via firewall: {ex.Message}");
            }
        }

        private void UnblockIpFromFirewall(string ip)
        {
            try
            {
                RunCommand("netsh", $"advfirewall firewall delete rule name=\"PCPlus Block {ip}\"");
                _context.Log(LogLevel.Info, Id, $"Firewall rule removed: unblock {ip}");
            }
            catch (Exception ex)
            {
                _context.Log(LogLevel.Warning, Id, $"Failed to unblock {ip}: {ex.Message}");
            }
        }

        #endregion

        #region Command Handlers

        private Task<ModuleResponse> HandleSetMode(ModuleCommand command)
        {
            var modeStr = command.Parameters?.GetValueOrDefault("mode") ?? "";
            if (Enum.TryParse<OperationMode>(modeStr, true, out var mode))
            {
                _mode = mode;
                _context.Log(LogLevel.Info, Id, $"Mode changed to: {mode}");
                return Task.FromResult(ModuleResponse.Ok($"Mode set to {mode}"));
            }
            return Task.FromResult(ModuleResponse.Fail($"Invalid mode: {modeStr}. Use: Passive, Active"));
        }

        private Task<ModuleResponse> HandleScanNow()
        {
            Task.Run(() =>
            {
                CollectWindowsSecurityEvents();
                ScanLocalNetwork();
            });
            return Task.FromResult(ModuleResponse.Ok("Scan initiated"));
        }

        private ModuleResponse GetStatusResponse()
        {
            lock (_dataLock)
            {
                var last24h = _loginEvents.Where(e => e.Timestamp >= DateTime.UtcNow.AddHours(-24)).ToList();
                return ModuleResponse.Ok("", new Dictionary<string, object>
                {
                    ["status"] = new
                    {
                        mode = _mode.ToString(),
                        isRunning = IsRunning,
                        uptime = (DateTime.UtcNow - _moduleStartTime).TotalMinutes,
                        stats = _stats,
                        last24h = new
                        {
                            totalEvents = last24h.Count,
                            failedLogins = last24h.Count(e => e.EventType == LoginEventType.FailedLogin),
                            successfulLogins = last24h.Count(e => e.EventType == LoginEventType.SuccessfulLogin),
                            accountLockouts = last24h.Count(e => e.EventType == LoginEventType.AccountLockout),
                            passwordChanges = last24h.Count(e => e.EventType == LoginEventType.PasswordChange),
                            privilegeEscalations = last24h.Count(e => e.EventType == LoginEventType.PrivilegeEscalation),
                            topSourceIPs = last24h
                                .Where(e => e.EventType == LoginEventType.FailedLogin && e.SourceIP != "Local")
                                .GroupBy(e => e.SourceIP)
                                .OrderByDescending(g => g.Count())
                                .Take(10)
                                .Select(g => new { ip = g.Key, count = g.Count() }),
                            topTargetAccounts = last24h
                                .Where(e => e.EventType == LoginEventType.FailedLogin)
                                .GroupBy(e => e.Username)
                                .OrderByDescending(g => g.Count())
                                .Take(10)
                                .Select(g => new { account = g.Key, count = g.Count() })
                        },
                        bruteForceAlerts = _bruteForceAlerts.Count,
                        portScanAlerts = _portScanAlerts.Count,
                        discoveredDevices = _discoveredDevices.Count,
                        blockedIps = _blockedIps.Count
                    }
                });
            }
        }

        private ModuleResponse GetLoginEventsResponse(ModuleCommand command)
        {
            var hours = 24;
            if (command.Parameters?.TryGetValue("hours", out var hoursStr) == true)
                int.TryParse(hoursStr, out hours);

            var filterType = command.Parameters?.GetValueOrDefault("type") ?? "";
            var filterProtocol = command.Parameters?.GetValueOrDefault("protocol") ?? "";

            lock (_dataLock)
            {
                var cutoff = DateTime.UtcNow.AddHours(-hours);
                var events = _loginEvents.Where(e => e.Timestamp >= cutoff);

                if (!string.IsNullOrEmpty(filterType) && Enum.TryParse<LoginEventType>(filterType, true, out var type))
                    events = events.Where(e => e.EventType == type);

                if (!string.IsNullOrEmpty(filterProtocol))
                    events = events.Where(e => e.Protocol.Equals(filterProtocol, StringComparison.OrdinalIgnoreCase));

                var result = events.OrderByDescending(e => e.Timestamp).Take(500).ToList();
                return ModuleResponse.Ok("", new Dictionary<string, object>
                {
                    ["events"] = result,
                    ["totalCount"] = result.Count,
                    ["timeRange"] = $"Last {hours} hours"
                });
            }
        }

        private ModuleResponse GetBruteForceAlertsResponse()
        {
            lock (_dataLock)
            {
                return ModuleResponse.Ok("", new Dictionary<string, object>
                {
                    ["alerts"] = _bruteForceAlerts.OrderByDescending(a => a.LastAttempt).Take(100).ToList(),
                    ["totalCount"] = _bruteForceAlerts.Count
                });
            }
        }

        private ModuleResponse GetDevicesResponse()
        {
            lock (_dataLock)
            {
                return ModuleResponse.Ok("", new Dictionary<string, object>
                {
                    ["devices"] = _discoveredDevices.OrderByDescending(d => d.LastSeen).ToList(),
                    ["totalCount"] = _discoveredDevices.Count
                });
            }
        }

        private ModuleResponse GetPortScanAlertsResponse()
        {
            lock (_dataLock)
            {
                return ModuleResponse.Ok("", new Dictionary<string, object>
                {
                    ["alerts"] = _portScanAlerts.OrderByDescending(a => a.DetectedAt).Take(100).ToList(),
                    ["totalCount"] = _portScanAlerts.Count
                });
            }
        }

        private ModuleResponse GetFullReportResponse()
        {
            lock (_dataLock)
            {
                var last24h = _loginEvents.Where(e => e.Timestamp >= DateTime.UtcNow.AddHours(-24)).ToList();
                var last7d = _loginEvents.Where(e => e.Timestamp >= DateTime.UtcNow.AddDays(-7)).ToList();

                var failedByHour = last24h
                    .Where(e => e.EventType == LoginEventType.FailedLogin)
                    .GroupBy(e => e.Timestamp.Hour)
                    .OrderBy(g => g.Key)
                    .Select(g => new { hour = g.Key, count = g.Count() })
                    .ToList();

                var failedByProtocol = last7d
                    .Where(e => e.EventType == LoginEventType.FailedLogin)
                    .GroupBy(e => e.Protocol)
                    .Select(g => new { protocol = g.Key, count = g.Count() })
                    .ToList();

                var topAttackers = last7d
                    .Where(e => e.EventType == LoginEventType.FailedLogin && e.SourceIP != "Local")
                    .GroupBy(e => e.SourceIP)
                    .OrderByDescending(g => g.Count())
                    .Take(20)
                    .Select(g => new
                    {
                        ip = g.Key,
                        count = g.Count(),
                        protocols = g.Select(e => e.Protocol).Distinct().ToList(),
                        targetAccounts = g.Select(e => e.Username).Distinct().Take(5).ToList(),
                        firstSeen = g.Min(e => e.Timestamp),
                        lastSeen = g.Max(e => e.Timestamp),
                        isBlocked = _blockedIps.Contains(g.Key)
                    })
                    .ToList();

                var successAfterFail = last7d
                    .Where(e => e.EventType == LoginEventType.SuccessfulLogin && e.SourceIP != "Local")
                    .Where(s => last7d.Any(f =>
                        f.EventType == LoginEventType.FailedLogin &&
                        f.SourceIP == s.SourceIP &&
                        f.Timestamp < s.Timestamp &&
                        (s.Timestamp - f.Timestamp).TotalMinutes < 30))
                    .Select(s => new
                    {
                        ip = s.SourceIP,
                        user = s.Username,
                        successTime = s.Timestamp,
                        protocol = s.Protocol,
                        priorFails = last7d.Count(f =>
                            f.EventType == LoginEventType.FailedLogin &&
                            f.SourceIP == s.SourceIP &&
                            f.Timestamp < s.Timestamp)
                    })
                    .ToList();

                return ModuleResponse.Ok("", new Dictionary<string, object>
                {
                    ["report"] = new
                    {
                        generatedAt = DateTime.UtcNow,
                        machineName = Environment.MachineName,
                        mode = _mode.ToString(),
                        summary = new
                        {
                            last24h_total = last24h.Count,
                            last24h_failed = last24h.Count(e => e.EventType == LoginEventType.FailedLogin),
                            last24h_success = last24h.Count(e => e.EventType == LoginEventType.SuccessfulLogin),
                            last7d_total = last7d.Count,
                            last7d_failed = last7d.Count(e => e.EventType == LoginEventType.FailedLogin),
                            last7d_success = last7d.Count(e => e.EventType == LoginEventType.SuccessfulLogin),
                            bruteForceAlerts = _bruteForceAlerts.Count,
                            portScanAlerts = _portScanAlerts.Count,
                            discoveredDevices = _discoveredDevices.Count,
                            blockedIps = _blockedIps.Count
                        },
                        failedByHour,
                        failedByProtocol,
                        topAttackers,
                        suspiciousSuccesses = successAfterFail,
                        activeBruteForce = _bruteForceAlerts
                            .Where(a => a.LastAttempt >= DateTime.UtcNow.AddHours(-1))
                            .OrderByDescending(a => a.AttemptCount)
                            .Take(10)
                            .ToList(),
                        discoveredDevices = _discoveredDevices,
                        blockedIps = _blockedIps.ToList()
                    }
                });
            }
        }

        #endregion

        #region Helpers

        private static string ExtractXmlValue(string xml, string name)
        {
            var pattern = $"Name='{name}'[^>]*>([^<]*)<";
            var match = Regex.Match(xml, pattern);
            return match.Success ? match.Groups[1].Value : "";
        }

        private static string ExtractIpFromMessage(string message)
        {
            var match = Regex.Match(message, @"(\d+\.\d+\.\d+\.\d+)");
            return match.Success ? match.Groups[1].Value : "";
        }

        private static string ExtractUserFromSshMessage(string message)
        {
            var match = Regex.Match(message, @"(?:user|for)\s+(\S+)", RegexOptions.IgnoreCase);
            return match.Success ? match.Groups[1].Value : "unknown";
        }

        private static string RunCommand(string command, string args)
        {
            try
            {
                var psi = new ProcessStartInfo(command, args)
                {
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using var proc = Process.Start(psi);
                if (proc == null) return "";
                var output = proc.StandardOutput.ReadToEnd();
                proc.WaitForExit(10000);
                return output;
            }
            catch
            {
                return "";
            }
        }

        #endregion

        #region Data Persistence

        private void PersistData()
        {
            try
            {
                lock (_dataLock)
                {
                    var opts = new JsonSerializerOptions
                    {
                        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                        WriteIndented = false
                    };

                    File.WriteAllText(EventsPath, JsonSerializer.Serialize(
                        _loginEvents.TakeLast(MAX_STORED_EVENTS).ToList(), opts));
                    File.WriteAllText(DevicesPath, JsonSerializer.Serialize(_discoveredDevices, opts));
                    File.WriteAllText(AlertsPath, JsonSerializer.Serialize(new
                    {
                        bruteForce = _bruteForceAlerts.TakeLast(MAX_STORED_ALERTS).ToList(),
                        portScan = _portScanAlerts.TakeLast(MAX_STORED_ALERTS).ToList()
                    }, opts));
                    File.WriteAllText(StatsPath, JsonSerializer.Serialize(_stats, opts));
                    File.WriteAllText(BlockedPath, JsonSerializer.Serialize(_blockedIps.ToList(), opts));
                }
            }
            catch (Exception ex)
            {
                _context.Log(LogLevel.Warning, Id, $"Data persist error: {ex.Message}");
            }
        }

        private void LoadPersistedData()
        {
            try
            {
                var opts = new JsonSerializerOptions
                {
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                    PropertyNameCaseInsensitive = true
                };

                if (File.Exists(EventsPath))
                {
                    var events = JsonSerializer.Deserialize<List<LoginEvent>>(File.ReadAllText(EventsPath), opts);
                    if (events != null) _loginEvents.AddRange(events);
                    if (_loginEvents.Count > 0)
                        _lastEventTime = _loginEvents.Max(e => e.Timestamp);
                }

                if (File.Exists(DevicesPath))
                {
                    var devices = JsonSerializer.Deserialize<List<NetworkDevice>>(File.ReadAllText(DevicesPath), opts);
                    if (devices != null) _discoveredDevices.AddRange(devices);
                }

                if (File.Exists(StatsPath))
                {
                    var stats = JsonSerializer.Deserialize<NetworkSecurityStats>(File.ReadAllText(StatsPath), opts);
                    if (stats != null) _stats = stats;
                }

                if (File.Exists(BlockedPath))
                {
                    var blocked = JsonSerializer.Deserialize<List<string>>(File.ReadAllText(BlockedPath), opts);
                    if (blocked != null) foreach (var ip in blocked) _blockedIps.Add(ip);
                }

                if (File.Exists(AlertsPath))
                {
                    var json = File.ReadAllText(AlertsPath);
                    using var doc = JsonDocument.Parse(json);
                    if (doc.RootElement.TryGetProperty("bruteForce", out var bf))
                    {
                        var alerts = JsonSerializer.Deserialize<List<BruteForceAlert>>(bf.GetRawText(), opts);
                        if (alerts != null) _bruteForceAlerts.AddRange(alerts);
                    }
                    if (doc.RootElement.TryGetProperty("portScan", out var ps))
                    {
                        var alerts = JsonSerializer.Deserialize<List<PortScanAlert>>(ps.GetRawText(), opts);
                        if (alerts != null) _portScanAlerts.AddRange(alerts);
                    }
                }
            }
            catch (Exception ex)
            {
                _context.Log(LogLevel.Warning, Id, $"Data load error: {ex.Message}");
            }
        }

        #endregion
    }

    #region Models

    public enum OperationMode
    {
        Passive,
        Active
    }

    public enum LoginEventType
    {
        SuccessfulLogin,
        FailedLogin,
        AccountLockout,
        PasswordChange,
        AccountCreated,
        AccountDeleted,
        GroupChange,
        ExplicitCredentials,
        PrivilegeEscalation
    }

    public class LoginEvent
    {
        public int EventId { get; set; }
        public LoginEventType EventType { get; set; }
        public DateTime Timestamp { get; set; }
        public string Username { get; set; } = "";
        public string SourceIP { get; set; } = "";
        public int SourcePort { get; set; }
        public string LogonType { get; set; } = "";
        public int LogonTypeId { get; set; }
        public string Protocol { get; set; } = "";
        public string ProcessName { get; set; } = "";
        public string WorkstationName { get; set; } = "";
        public string FailureReason { get; set; } = "";
        public string Detail { get; set; } = "";
    }

    public class BruteForceAlert
    {
        public string Id { get; set; } = Guid.NewGuid().ToString("N")[..12];
        public string SourceIP { get; set; } = "";
        public string Protocol { get; set; } = "";
        public int AttemptCount { get; set; }
        public DateTime FirstAttempt { get; set; }
        public DateTime LastAttempt { get; set; }
        public List<string> TargetAccounts { get; set; } = new();
        public bool IsBlocked { get; set; }
    }

    public class PortScanAlert
    {
        public string Id { get; set; } = Guid.NewGuid().ToString("N")[..12];
        public string SourceIP { get; set; } = "";
        public int ConnectionCount { get; set; }
        public DateTime DetectedAt { get; set; }
    }

    public class NetworkDevice
    {
        public string IPAddress { get; set; } = "";
        public string MACAddress { get; set; } = "";
        public string? Hostname { get; set; }
        public string? Vendor { get; set; }
        public string Type { get; set; } = "";
        public DateTime FirstSeen { get; set; }
        public DateTime LastSeen { get; set; }
        public bool IsKnown { get; set; }
    }

    public class NetworkSecurityStats
    {
        public int TotalEventsCollected { get; set; }
        public int FailedLoginCount { get; set; }
        public int SuccessfulLoginCount { get; set; }
        public int BruteForceAlertsRaised { get; set; }
        public int PortScanAlertsRaised { get; set; }
        public int NewDevicesFound { get; set; }
        public DateTime LastCollectionTime { get; set; }
    }

    public class LoginAttemptTracker
    {
        public string IP { get; set; } = "";
        public string Protocol { get; set; } = "";
        public List<AttemptRecord> Attempts { get; set; } = new();
    }

    public class AttemptRecord
    {
        public DateTime Timestamp { get; set; }
        public string Username { get; set; } = "";
        public bool Success { get; set; }
    }

    public class ConnectionTracker
    {
        public string IP { get; set; } = "";
        public List<ConnectionRecord> RecentConnections { get; set; } = new();
    }

    public class ConnectionRecord
    {
        public DateTime Timestamp { get; set; }
        public int Count { get; set; }
    }

    #endregion
}
