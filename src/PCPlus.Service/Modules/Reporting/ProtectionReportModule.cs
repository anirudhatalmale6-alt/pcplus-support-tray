using System.Text.Json;
using PCPlus.Core.Interfaces;
using PCPlus.Core.Models;

namespace PCPlus.Service.Modules.Reporting
{
    public class ProtectionReportModule : IModule
    {
        public string Id => "reporting";
        public string Name => "Protection Reports";
        public string Version => "1.0.0";
        public LicenseTier RequiredTier => LicenseTier.Free;
        public bool IsRunning { get; private set; }

        private IModuleContext _context = null!;
        private Timer? _snapshotTimer;
        private Timer? _reportTimer;
        private readonly object _lock = new();

        private ProtectionHistory _history = new();
        private ProtectionSnapshot _currentSnapshot = new();
        private DateTime _serviceStartTime;

        private static readonly string DataDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "PCPlusEndpoint", "reports");

        private static readonly string HistoryFile = Path.Combine(DataDir, "protection-history.json");
        private static readonly string ReportDir = Path.Combine(DataDir, "html");

        public Task InitializeAsync(IModuleContext context)
        {
            _context = context;
            Directory.CreateDirectory(DataDir);
            Directory.CreateDirectory(ReportDir);
            LoadHistory();
            return Task.CompletedTask;
        }

        public Task StartAsync(CancellationToken cancellationToken)
        {
            IsRunning = true;
            _serviceStartTime = DateTime.UtcNow;
            _currentSnapshot = new ProtectionSnapshot { Date = DateTime.UtcNow.Date };

            // Collect stats every 5 minutes
            _snapshotTimer = new Timer(_ => CollectSnapshot(), null,
                TimeSpan.FromMinutes(2), TimeSpan.FromMinutes(5));

            // Generate HTML report every hour
            _reportTimer = new Timer(_ => GenerateReport(), null,
                TimeSpan.FromMinutes(5), TimeSpan.FromHours(1));

            _context.Log(LogLevel.Info, Id, "Protection Reports active. Tracking value metrics.");
            return Task.CompletedTask;
        }

        public Task StopAsync()
        {
            IsRunning = false;
            _snapshotTimer?.Dispose();
            _reportTimer?.Dispose();
            FinalizeSnapshot();
            SaveHistory();
            GenerateReport();
            return Task.CompletedTask;
        }

        public Task<ModuleResponse> HandleCommandAsync(ModuleCommand command)
        {
            switch (command.Action.ToLowerInvariant())
            {
                case "getsummary":
                    return Task.FromResult(ModuleResponse.Ok("Protection summary", BuildSummaryData()));

                case "gethistory":
                    int days = 30;
                    if (command.Parameters.TryGetValue("days", out var d))
                        int.TryParse(d, out days);
                    return Task.FromResult(ModuleResponse.Ok("Protection history", BuildHistoryData(days)));

                case "getscore":
                    return Task.FromResult(ModuleResponse.Ok("Protection score",
                        new Dictionary<string, object>
                        {
                            ["score"] = CalculateProtectionScore(),
                            ["breakdown"] = GetScoreBreakdown()
                        }));

                case "generatereport":
                    GenerateReport();
                    return Task.FromResult(ModuleResponse.Ok("Report generated",
                        new Dictionary<string, object>
                        {
                            ["path"] = Path.Combine(ReportDir, "latest-report.html")
                        }));

                case "getreportpath":
                    return Task.FromResult(ModuleResponse.Ok("",
                        new Dictionary<string, object>
                        {
                            ["path"] = Path.Combine(ReportDir, "latest-report.html")
                        }));

                case "event":
                    return Task.FromResult(ModuleResponse.Ok());

                default:
                    return Task.FromResult(ModuleResponse.Fail($"Unknown action: {command.Action}"));
            }
        }

        public ModuleStatus GetStatus()
        {
            var score = CalculateProtectionScore();
            return new ModuleStatus
            {
                ModuleId = Id,
                ModuleName = Name,
                IsRunning = IsRunning,
                RequiredTier = RequiredTier,
                StatusText = $"Score: {score}/100, {_history.DailySnapshots.Count} days tracked",
                LastActivity = DateTime.UtcNow,
                Metrics = new Dictionary<string, object>
                {
                    ["protectionScore"] = score,
                    ["daysTracked"] = _history.DailySnapshots.Count,
                    ["totalThreatsBlocked"] = _history.DailySnapshots.Sum(s => s.TotalThreatsBlocked),
                    ["totalLinksScanned"] = _history.DailySnapshots.Sum(s => s.LinksScanned),
                    ["totalDnsBlocked"] = _history.DailySnapshots.Sum(s => s.DnsQueriesBlocked),
                    ["uptimeHours"] = (DateTime.UtcNow - _serviceStartTime).TotalHours
                }
            };
        }

        #region Stats Collection

        private void CollectSnapshot()
        {
            try
            {
                var today = DateTime.UtcNow.Date;

                lock (_lock)
                {
                    // Roll over to new day if needed
                    if (_currentSnapshot.Date != today)
                    {
                        FinalizeSnapshot();
                        _currentSnapshot = new ProtectionSnapshot { Date = today };
                    }
                }

                // Collect from all modules
                CollectFromHealth();
                CollectFromSecurity();
                CollectFromRansomware();
                CollectFromPhishing();
                CollectFromCustomerValue();

                lock (_lock)
                {
                    _currentSnapshot.LastUpdated = DateTime.UtcNow;
                    _currentSnapshot.UptimeMinutes += 5;
                }
            }
            catch (Exception ex)
            {
                _context.Log(LogLevel.Warning, Id, $"Snapshot collection error: {ex.Message}");
            }
        }

        private void CollectFromHealth()
        {
            var module = _context.GetModule("health");
            if (module == null || !module.IsRunning) return;

            var status = module.GetStatus();
            lock (_lock)
            {
                _currentSnapshot.HealthChecksRun++;
                if (status.Metrics.TryGetValue("overallScore", out var score) && score is int s)
                    _currentSnapshot.SystemHealthScore = s;
            }
        }

        private void CollectFromSecurity()
        {
            var module = _context.GetModule("security");
            if (module == null || !module.IsRunning) return;

            var status = module.GetStatus();
            lock (_lock)
            {
                if (status.Metrics.TryGetValue("totalAlerts", out var alerts))
                    _currentSnapshot.SecurityAlertsRaised = Convert.ToInt32(alerts);
                if (status.Metrics.TryGetValue("processesBlocked", out var blocked))
                    _currentSnapshot.ProcessesBlocked = Convert.ToInt32(blocked);
                if (status.Metrics.TryGetValue("usbEventsDetected", out var usb))
                    _currentSnapshot.UsbEventsDetected = Convert.ToInt32(usb);
                if (status.Metrics.TryGetValue("geoIpBlocked", out var geo))
                    _currentSnapshot.GeoIpConnectionsBlocked = Convert.ToInt32(geo);
            }
        }

        private void CollectFromRansomware()
        {
            var module = _context.GetModule("ransomware");
            if (module == null || !module.IsRunning) return;

            var status = module.GetStatus();
            lock (_lock)
            {
                if (status.Metrics.TryGetValue("snapshots", out var snaps))
                    _currentSnapshot.VssSnapshotsProtected = Convert.ToInt32(snaps);
                if (status.Metrics.TryGetValue("hardenedExes", out var hard))
                    _currentSnapshot.ExecutablesHardened = Convert.ToInt32(hard);
                if (status.Metrics.TryGetValue("threatsBlocked", out var threats))
                    _currentSnapshot.RansomwareThreatsBlocked = Convert.ToInt32(threats);
            }
        }

        private void CollectFromPhishing()
        {
            var module = _context.GetModule("phishing");
            if (module == null || !module.IsRunning) return;

            var status = module.GetStatus();
            lock (_lock)
            {
                if (status.Metrics.TryGetValue("totalBlocked", out var blocked))
                    _currentSnapshot.PhishingDomainsBlocked = Convert.ToInt32(blocked);
                if (status.Metrics.TryGetValue("blockedDomainCount", out var domains))
                    _currentSnapshot.DomainBlocklistSize = Convert.ToInt32(domains);
                if (status.Metrics.TryGetValue("dnsQueries", out var queries))
                    _currentSnapshot.DnsQueriesProcessed = Convert.ToInt64(queries);
                if (status.Metrics.TryGetValue("dnsBlocked", out var dnsBlocked))
                    _currentSnapshot.DnsQueriesBlocked = Convert.ToInt64(dnsBlocked);
                if (status.Metrics.TryGetValue("dnsOverTls", out var dot) && dot is bool dotEnabled)
                    _currentSnapshot.DnsOverTlsActive = dotEnabled;
                if (status.Metrics.TryGetValue("dnsAntiBypass", out var bypass))
                    _currentSnapshot.DnsBypassAttempts = Convert.ToInt32(bypass);
                if (status.Metrics.TryGetValue("eventsLast24h", out var events))
                    _currentSnapshot.PhishingEventsToday = Convert.ToInt32(events);

                _currentSnapshot.LinksScanned = _currentSnapshot.DnsQueriesProcessed;
                _currentSnapshot.TotalThreatsBlocked = _currentSnapshot.PhishingDomainsBlocked +
                    _currentSnapshot.RansomwareThreatsBlocked + _currentSnapshot.ProcessesBlocked +
                    _currentSnapshot.GeoIpConnectionsBlocked + (int)_currentSnapshot.DnsQueriesBlocked;
            }
        }

        private void CollectFromCustomerValue()
        {
            var module = _context.GetModule("customervalue");
            if (module == null || !module.IsRunning) return;

            var status = module.GetStatus();
            lock (_lock)
            {
                if (status.Metrics.TryGetValue("breachedAccounts", out var breached))
                    _currentSnapshot.BreachedAccountsFound = Convert.ToInt32(breached);
                if (status.Metrics.TryGetValue("unsecureNetworks", out var unsecure))
                    _currentSnapshot.UnsecureWifiDetected = Convert.ToInt32(unsecure);
            }
        }

        private void FinalizeSnapshot()
        {
            lock (_lock)
            {
                if (_currentSnapshot.Date == default) return;
                _currentSnapshot.LastUpdated = DateTime.UtcNow;
                _currentSnapshot.ProtectionScore = CalculateProtectionScore();

                // Replace if same date exists, otherwise add
                var existing = _history.DailySnapshots.FindIndex(s => s.Date == _currentSnapshot.Date);
                if (existing >= 0)
                    _history.DailySnapshots[existing] = _currentSnapshot;
                else
                    _history.DailySnapshots.Add(_currentSnapshot);

                // Keep last 365 days
                if (_history.DailySnapshots.Count > 365)
                    _history.DailySnapshots.RemoveRange(0, _history.DailySnapshots.Count - 365);
            }
            SaveHistory();
        }

        #endregion

        #region Protection Score

        private int CalculateProtectionScore()
        {
            int score = 0;
            int maxScore = 0;

            // DNS Protection (25 points)
            maxScore += 25;
            var phishing = _context.GetModule("phishing");
            if (phishing?.IsRunning == true)
            {
                score += 15;
                var status = phishing.GetStatus();
                if (status.Metrics.TryGetValue("dnsOverTls", out var dot) && dot is true)
                    score += 5;
                if (status.Metrics.TryGetValue("blockedDomainCount", out var bl) && Convert.ToInt32(bl) > 1000)
                    score += 5;
            }

            // Ransomware Protection (20 points)
            maxScore += 20;
            var ransomware = _context.GetModule("ransomware");
            if (ransomware?.IsRunning == true)
            {
                score += 10;
                var status = ransomware.GetStatus();
                if (status.Metrics.TryGetValue("snapshots", out var snaps) && Convert.ToInt32(snaps) > 0)
                    score += 5;
                if (status.Metrics.TryGetValue("hardenedExes", out var hard) && Convert.ToInt32(hard) > 0)
                    score += 5;
            }

            // Security Monitoring (20 points)
            maxScore += 20;
            var security = _context.GetModule("security");
            if (security?.IsRunning == true)
            {
                score += 10;
                var status = security.GetStatus();
                if (status.Metrics.TryGetValue("selfProtectionActive", out var sp) && sp is true)
                    score += 5;
                if (status.Metrics.TryGetValue("geoIpActive", out var geo) && geo is true)
                    score += 5;
            }

            // Health Monitoring (15 points)
            maxScore += 15;
            var health = _context.GetModule("health");
            if (health?.IsRunning == true)
            {
                score += 10;
                var status = health.GetStatus();
                if (status.Metrics.TryGetValue("overallScore", out var hs) && Convert.ToInt32(hs) > 70)
                    score += 5;
            }

            // System Maintenance (10 points)
            maxScore += 10;
            var maintenance = _context.GetModule("maintenance");
            if (maintenance?.IsRunning == true)
                score += 10;

            // Customer Value Features (10 points)
            maxScore += 10;
            var cv = _context.GetModule("customervalue");
            if (cv?.IsRunning == true)
                score += 10;

            return maxScore > 0 ? Math.Min(100, (score * 100) / maxScore) : 0;
        }

        private Dictionary<string, object> GetScoreBreakdown()
        {
            var breakdown = new Dictionary<string, object>();

            void AddCategory(string name, string moduleId, int maxPts)
            {
                var module = _context.GetModule(moduleId);
                breakdown[name] = new Dictionary<string, object>
                {
                    ["active"] = module?.IsRunning ?? false,
                    ["maxPoints"] = maxPts,
                    ["status"] = module?.IsRunning == true ? "Protected" : "Inactive"
                };
            }

            AddCategory("DNS & Phishing Protection", "phishing", 25);
            AddCategory("Ransomware Protection", "ransomware", 20);
            AddCategory("Security Monitoring", "security", 20);
            AddCategory("Health Monitoring", "health", 15);
            AddCategory("System Maintenance", "maintenance", 10);
            AddCategory("Customer Value Features", "customervalue", 10);

            return breakdown;
        }

        #endregion

        #region Summary & History Data

        private Dictionary<string, object> BuildSummaryData()
        {
            var score = CalculateProtectionScore();
            var today = GetTodaySnapshot();
            var last7 = GetSnapshots(7);
            var last30 = GetSnapshots(30);

            return new Dictionary<string, object>
            {
                ["protectionScore"] = score,
                ["scoreLabel"] = score >= 80 ? "Excellent" : score >= 60 ? "Good" : score >= 40 ? "Fair" : "Needs Attention",
                ["uptime"] = new Dictionary<string, object>
                {
                    ["hours"] = Math.Round((DateTime.UtcNow - _serviceStartTime).TotalHours, 1),
                    ["since"] = _serviceStartTime.ToString("o")
                },
                ["today"] = new Dictionary<string, object>
                {
                    ["threatsBlocked"] = today.TotalThreatsBlocked,
                    ["linksScanned"] = today.LinksScanned,
                    ["dnsBlocked"] = today.DnsQueriesBlocked,
                    ["phishingBlocked"] = today.PhishingDomainsBlocked
                },
                ["last7Days"] = new Dictionary<string, object>
                {
                    ["threatsBlocked"] = last7.Sum(s => s.TotalThreatsBlocked),
                    ["linksScanned"] = last7.Sum(s => s.LinksScanned),
                    ["dnsBlocked"] = last7.Sum(s => s.DnsQueriesBlocked),
                    ["avgScore"] = last7.Count > 0 ? last7.Average(s => s.ProtectionScore) : 0
                },
                ["last30Days"] = new Dictionary<string, object>
                {
                    ["threatsBlocked"] = last30.Sum(s => s.TotalThreatsBlocked),
                    ["linksScanned"] = last30.Sum(s => s.LinksScanned),
                    ["dnsBlocked"] = last30.Sum(s => s.DnsQueriesBlocked),
                    ["avgScore"] = last30.Count > 0 ? last30.Average(s => s.ProtectionScore) : 0
                },
                ["activeProtections"] = new Dictionary<string, object>
                {
                    ["dnsFilterProxy"] = _context.GetModule("phishing")?.IsRunning ?? false,
                    ["dnsOverTls"] = today.DnsOverTlsActive,
                    ["ransomwareGuard"] = _context.GetModule("ransomware")?.IsRunning ?? false,
                    ["securityMonitor"] = _context.GetModule("security")?.IsRunning ?? false,
                    ["healthMonitor"] = _context.GetModule("health")?.IsRunning ?? false,
                    ["geoIpBlocking"] = today.GeoIpConnectionsBlocked > 0,
                    ["usbMonitor"] = true,
                    ["browserExtension"] = true,
                    ["domainBlocklistSize"] = today.DomainBlocklistSize
                },
                ["highlights"] = BuildHighlights(today, last7, last30)
            };
        }

        private List<string> BuildHighlights(ProtectionSnapshot today, List<ProtectionSnapshot> week, List<ProtectionSnapshot> month)
        {
            var highlights = new List<string>();

            var totalBlocked = month.Sum(s => s.TotalThreatsBlocked);
            if (totalBlocked > 0)
                highlights.Add($"Blocked {totalBlocked:N0} threats in the last 30 days");

            var dnsBlocked = month.Sum(s => s.DnsQueriesBlocked);
            if (dnsBlocked > 0)
                highlights.Add($"Filtered {dnsBlocked:N0} malicious DNS queries");

            if (today.DnsOverTlsActive)
                highlights.Add("All DNS queries are encrypted via DNS-over-TLS");

            var phishing = month.Sum(s => s.PhishingDomainsBlocked);
            if (phishing > 0)
                highlights.Add($"Prevented {phishing:N0} phishing attempts");

            if (today.VssSnapshotsProtected > 0)
                highlights.Add($"{today.VssSnapshotsProtected} volume shadow copies protected against ransomware");

            if (today.ExecutablesHardened > 0)
                highlights.Add($"{today.ExecutablesHardened} critical executables hardened against tampering");

            var geoBlocked = month.Sum(s => s.GeoIpConnectionsBlocked);
            if (geoBlocked > 0)
                highlights.Add($"Blocked {geoBlocked:N0} connections from high-risk countries");

            if (today.DnsBypassAttempts > 0)
                highlights.Add($"Detected and prevented {today.DnsBypassAttempts} DNS bypass attempts");

            if (today.BreachedAccountsFound > 0)
                highlights.Add($"Found {today.BreachedAccountsFound} accounts in data breaches - password change recommended");

            if (highlights.Count == 0)
                highlights.Add("System is protected and monitoring for threats");

            return highlights;
        }

        private Dictionary<string, object> BuildHistoryData(int days)
        {
            var snapshots = GetSnapshots(days);
            return new Dictionary<string, object>
            {
                ["days"] = days,
                ["snapshots"] = snapshots.Select(s => new Dictionary<string, object>
                {
                    ["date"] = s.Date.ToString("yyyy-MM-dd"),
                    ["score"] = s.ProtectionScore,
                    ["threatsBlocked"] = s.TotalThreatsBlocked,
                    ["linksScanned"] = s.LinksScanned,
                    ["dnsBlocked"] = s.DnsQueriesBlocked,
                    ["phishingBlocked"] = s.PhishingDomainsBlocked,
                    ["uptimeMinutes"] = s.UptimeMinutes
                }).ToList()
            };
        }

        private ProtectionSnapshot GetTodaySnapshot()
        {
            lock (_lock) { return _currentSnapshot; }
        }

        private List<ProtectionSnapshot> GetSnapshots(int days)
        {
            var cutoff = DateTime.UtcNow.Date.AddDays(-days);
            lock (_lock)
            {
                var list = _history.DailySnapshots
                    .Where(s => s.Date >= cutoff)
                    .OrderBy(s => s.Date)
                    .ToList();
                if (_currentSnapshot.Date >= cutoff)
                    list.Add(_currentSnapshot);
                return list;
            }
        }

        #endregion

        #region HTML Report Generator

        private void GenerateReport()
        {
            try
            {
                var summary = BuildSummaryData();
                var score = (int)(summary["protectionScore"] ?? 0);
                var scoreLabel = summary["scoreLabel"]?.ToString() ?? "Unknown";
                var today = (Dictionary<string, object>)summary["today"];
                var week = (Dictionary<string, object>)summary["last7Days"];
                var month = (Dictionary<string, object>)summary["last30Days"];
                var protections = (Dictionary<string, object>)summary["activeProtections"];
                var highlights = (List<string>)summary["highlights"];

                var scoreColor = score >= 80 ? "#22c55e" : score >= 60 ? "#f59e0b" : "#ef4444";
                var now = DateTime.Now;

                var html = $@"<!DOCTYPE html>
<html lang=""en"">
<head>
<meta charset=""UTF-8"">
<meta name=""viewport"" content=""width=device-width, initial-scale=1.0"">
<title>PC Plus Protection Report</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0a0e1a; color: #e2e8f0; min-height: 100vh; }}
.report {{ max-width: 900px; margin: 0 auto; padding: 32px 24px; }}
.header {{ text-align: center; padding: 32px 0; border-bottom: 1px solid #1e3a5f; margin-bottom: 32px; }}
.logo {{ font-size: 48px; margin-bottom: 12px; }}
.brand {{ font-size: 24px; font-weight: 700; color: #ffffff; }}
.tagline {{ font-size: 13px; color: #60a5fa; margin-top: 4px; letter-spacing: 2px; text-transform: uppercase; }}
.report-date {{ font-size: 13px; color: #64748b; margin-top: 16px; }}
.score-section {{ text-align: center; padding: 40px 0; }}
.score-ring {{ width: 180px; height: 180px; margin: 0 auto 20px; position: relative; }}
.score-ring svg {{ width: 100%; height: 100%; transform: rotate(-90deg); }}
.score-ring circle {{ fill: none; stroke-width: 8; }}
.score-bg {{ stroke: #1e293b; }}
.score-fg {{ stroke: {scoreColor}; stroke-linecap: round; stroke-dasharray: {score * 5.02} 502; transition: stroke-dasharray 1s ease; }}
.score-value {{ position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); font-size: 48px; font-weight: 800; color: {scoreColor}; }}
.score-label {{ font-size: 20px; color: {scoreColor}; font-weight: 600; margin-bottom: 8px; }}
.score-sub {{ font-size: 14px; color: #94a3b8; }}
.stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin: 32px 0; }}
.stat-card {{ background: linear-gradient(135deg, rgba(30, 58, 95, 0.3), rgba(15, 23, 41, 0.8)); border: 1px solid #1e3a5f; border-radius: 12px; padding: 20px; text-align: center; }}
.stat-value {{ font-size: 32px; font-weight: 800; background: linear-gradient(135deg, #60a5fa, #3b82f6); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; }}
.stat-value.danger {{ background: linear-gradient(135deg, #ef4444, #dc2626); -webkit-background-clip: text; background-clip: text; }}
.stat-value.success {{ background: linear-gradient(135deg, #22c55e, #16a34a); -webkit-background-clip: text; background-clip: text; }}
.stat-label {{ font-size: 12px; color: #94a3b8; margin-top: 4px; text-transform: uppercase; letter-spacing: 1px; }}
.stat-period {{ font-size: 11px; color: #475569; margin-top: 2px; }}
.section {{ margin: 32px 0; }}
.section-title {{ font-size: 18px; font-weight: 700; color: #ffffff; margin-bottom: 16px; padding-bottom: 8px; border-bottom: 1px solid #1e3a5f; }}
.protection-list {{ list-style: none; }}
.protection-item {{ display: flex; align-items: center; gap: 12px; padding: 10px 0; border-bottom: 1px solid rgba(30, 58, 95, 0.5); }}
.protection-icon {{ font-size: 20px; width: 32px; text-align: center; }}
.protection-name {{ font-size: 14px; color: #e2e8f0; flex: 1; }}
.protection-status {{ font-size: 12px; font-weight: 600; padding: 4px 12px; border-radius: 20px; }}
.status-active {{ background: rgba(34, 197, 94, 0.15); color: #22c55e; }}
.status-inactive {{ background: rgba(239, 68, 68, 0.15); color: #ef4444; }}
.highlight-list {{ list-style: none; }}
.highlight-item {{ padding: 10px 16px; margin: 6px 0; background: rgba(59, 130, 246, 0.08); border-left: 3px solid #3b82f6; border-radius: 0 8px 8px 0; font-size: 14px; color: #cbd5e1; }}
.period-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin-top: 16px; }}
.period-card {{ background: rgba(255,255,255,0.02); border: 1px solid #1e3a5f; border-radius: 10px; padding: 16px; }}
.period-title {{ font-size: 13px; color: #60a5fa; font-weight: 600; margin-bottom: 12px; }}
.period-stat {{ display: flex; justify-content: space-between; padding: 4px 0; font-size: 13px; }}
.period-stat-label {{ color: #94a3b8; }}
.period-stat-value {{ color: #e2e8f0; font-weight: 600; }}
.footer {{ text-align: center; padding: 32px 0; margin-top: 32px; border-top: 1px solid #1e3a5f; }}
.footer-text {{ font-size: 12px; color: #475569; }}
.footer-link {{ color: #60a5fa; text-decoration: none; }}
.print-btn {{ display: inline-block; margin: 16px auto; padding: 10px 24px; background: #3b82f6; color: white; border: none; border-radius: 8px; font-size: 14px; cursor: pointer; text-decoration: none; }}
.print-btn:hover {{ opacity: 0.85; }}
@media print {{ .print-btn {{ display: none; }} body {{ background: white; color: #1a1a1a; }} .stat-card, .period-card {{ border-color: #ddd; }} .section-title {{ color: #1a1a1a; }} .protection-name {{ color: #333; }} }}
</style>
</head>
<body>
<div class=""report"">
<div class=""header"">
<div class=""logo"">&#x1f6e1;&#xfe0f;</div>
<div class=""brand"">PC Plus Endpoint Protection</div>
<div class=""tagline"">Monitor &middot; Protect &middot; Secure</div>
<div class=""report-date"">Protection Report &mdash; Generated {now:MMMM d, yyyy} at {now:h:mm tt}</div>
</div>

<div class=""score-section"">
<div class=""score-ring"">
<svg viewBox=""0 0 170 170""><circle class=""score-bg"" cx=""85"" cy=""85"" r=""80""/><circle class=""score-fg"" cx=""85"" cy=""85"" r=""80""/></svg>
<div class=""score-value"">{score}</div>
</div>
<div class=""score-label"">{scoreLabel} Protection</div>
<div class=""score-sub"">Your system is {"well protected" + (score >= 80 ? "" : " but could be stronger")}</div>
</div>

<div class=""stats-grid"">
<div class=""stat-card""><div class=""stat-value danger"">{FormatNumber(Convert.ToInt64(month["threatsBlocked"]))}</div><div class=""stat-label"">Threats Blocked</div><div class=""stat-period"">Last 30 Days</div></div>
<div class=""stat-card""><div class=""stat-value"">{FormatNumber(Convert.ToInt64(month["linksScanned"]))}</div><div class=""stat-label"">Links Scanned</div><div class=""stat-period"">Last 30 Days</div></div>
<div class=""stat-card""><div class=""stat-value danger"">{FormatNumber(Convert.ToInt64(month["dnsBlocked"]))}</div><div class=""stat-label"">DNS Queries Blocked</div><div class=""stat-period"">Last 30 Days</div></div>
<div class=""stat-card""><div class=""stat-value success"">{score}/100</div><div class=""stat-label"">Protection Score</div><div class=""stat-period"">Current</div></div>
</div>

<div class=""section"">
<div class=""section-title"">Protection Breakdown</div>
<div class=""period-grid"">
<div class=""period-card"">
<div class=""period-title"">Today</div>
<div class=""period-stat""><span class=""period-stat-label"">Threats Blocked</span><span class=""period-stat-value"">{today["threatsBlocked"]}</span></div>
<div class=""period-stat""><span class=""period-stat-label"">Links Scanned</span><span class=""period-stat-value"">{FormatNumber(Convert.ToInt64(today["linksScanned"]))}</span></div>
<div class=""period-stat""><span class=""period-stat-label"">DNS Blocked</span><span class=""period-stat-value"">{today["dnsBlocked"]}</span></div>
<div class=""period-stat""><span class=""period-stat-label"">Phishing Blocked</span><span class=""period-stat-value"">{today["phishingBlocked"]}</span></div>
</div>
<div class=""period-card"">
<div class=""period-title"">Last 7 Days</div>
<div class=""period-stat""><span class=""period-stat-label"">Threats Blocked</span><span class=""period-stat-value"">{week["threatsBlocked"]}</span></div>
<div class=""period-stat""><span class=""period-stat-label"">Links Scanned</span><span class=""period-stat-value"">{FormatNumber(Convert.ToInt64(week["linksScanned"]))}</span></div>
<div class=""period-stat""><span class=""period-stat-label"">DNS Blocked</span><span class=""period-stat-value"">{week["dnsBlocked"]}</span></div>
<div class=""period-stat""><span class=""period-stat-label"">Avg Score</span><span class=""period-stat-value"">{Convert.ToDouble(week["avgScore"]):F0}</span></div>
</div>
<div class=""period-card"">
<div class=""period-title"">Last 30 Days</div>
<div class=""period-stat""><span class=""period-stat-label"">Threats Blocked</span><span class=""period-stat-value"">{month["threatsBlocked"]}</span></div>
<div class=""period-stat""><span class=""period-stat-label"">Links Scanned</span><span class=""period-stat-value"">{FormatNumber(Convert.ToInt64(month["linksScanned"]))}</span></div>
<div class=""period-stat""><span class=""period-stat-label"">DNS Blocked</span><span class=""period-stat-value"">{month["dnsBlocked"]}</span></div>
<div class=""period-stat""><span class=""period-stat-label"">Avg Score</span><span class=""period-stat-value"">{Convert.ToDouble(month["avgScore"]):F0}</span></div>
</div>
</div>
</div>

<div class=""section"">
<div class=""section-title"">Active Protections</div>
<ul class=""protection-list"">
{BuildProtectionListHtml(protections)}
</ul>
</div>

<div class=""section"">
<div class=""section-title"">Key Highlights</div>
<ul class=""highlight-list"">
{string.Join("\n", highlights.Select(h => $"<li class=\"highlight-item\">{EscapeHtml(h)}</li>"))}
</ul>
</div>

<div style=""text-align: center; margin-top: 24px;"">
<a class=""print-btn"" href=""javascript:window.print()"">Print / Save as PDF</a>
</div>

<div class=""footer"">
<div class=""footer-text"">Protected by <a class=""footer-link"" href=""https://pcpluscomputing.com"">PC Plus Computing</a> &mdash; Monitor. Protect. Secure.</div>
<div class=""footer-text"" style=""margin-top: 8px;"">This report was automatically generated. For questions, contact your IT administrator.</div>
</div>
</div>
</body>
</html>";

                File.WriteAllText(Path.Combine(ReportDir, "latest-report.html"), html);

                // Also save dated version
                var dated = Path.Combine(ReportDir, $"report-{now:yyyy-MM-dd}.html");
                File.WriteAllText(dated, html);

                // Clean old reports (keep last 90)
                var files = Directory.GetFiles(ReportDir, "report-*.html")
                    .OrderByDescending(f => f).Skip(90).ToList();
                foreach (var f in files) try { File.Delete(f); } catch { }

                _context.Log(LogLevel.Info, Id, "Protection report generated.");
            }
            catch (Exception ex)
            {
                _context.Log(LogLevel.Warning, Id, $"Report generation error: {ex.Message}");
            }
        }

        private static string BuildProtectionListHtml(Dictionary<string, object> protections)
        {
            var items = new (string icon, string name, string key)[]
            {
                ("\U0001f310", "DNS Filter Proxy (System-wide)", "dnsFilterProxy"),
                ("\U0001f512", "DNS-over-TLS Encryption", "dnsOverTls"),
                ("\U0001f6e1", "Ransomware Guard", "ransomwareGuard"),
                ("\U0001f50d", "Security Monitor", "securityMonitor"),
                ("\U0001f4ca", "Health Monitor", "healthMonitor"),
                ("\U0001f30d", "GeoIP Country Blocking", "geoIpBlocking"),
                ("\U0001f50c", "USB Device Monitor", "usbMonitor"),
                ("\U0001f310", "Browser Extension (Email Link Scanner)", "browserExtension"),
            };

            var sb = new System.Text.StringBuilder();
            foreach (var (icon, name, key) in items)
            {
                var active = protections.TryGetValue(key, out var val) && val is true;
                var statusClass = active ? "status-active" : "status-inactive";
                var statusText = active ? "Active" : "Inactive";
                sb.AppendLine($"<li class=\"protection-item\"><span class=\"protection-icon\">{icon}</span><span class=\"protection-name\">{name}</span><span class=\"protection-status {statusClass}\">{statusText}</span></li>");
            }

            if (protections.TryGetValue("domainBlocklistSize", out var size))
                sb.AppendLine($"<li class=\"protection-item\"><span class=\"protection-icon\">\U0001f4cb</span><span class=\"protection-name\">Domain Blocklist</span><span class=\"protection-status status-active\">{Convert.ToInt32(size):N0} domains</span></li>");

            return sb.ToString();
        }

        private static string FormatNumber(long num)
        {
            if (num >= 1_000_000) return $"{num / 1_000_000.0:F1}M";
            if (num >= 1_000) return $"{num / 1_000.0:F1}K";
            return num.ToString("N0");
        }

        private static string EscapeHtml(string text)
        {
            return text.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;");
        }

        #endregion

        #region Persistence

        private void SaveHistory()
        {
            try
            {
                lock (_lock)
                {
                    var json = JsonSerializer.Serialize(_history, new JsonSerializerOptions { WriteIndented = true });
                    File.WriteAllText(HistoryFile, json);
                }
            }
            catch { }
        }

        private void LoadHistory()
        {
            if (!File.Exists(HistoryFile)) return;
            try
            {
                var json = File.ReadAllText(HistoryFile);
                _history = JsonSerializer.Deserialize<ProtectionHistory>(json) ?? new();
            }
            catch { _history = new(); }
        }

        #endregion
    }

    #region Models

    public class ProtectionHistory
    {
        public List<ProtectionSnapshot> DailySnapshots { get; set; } = new();
    }

    public class ProtectionSnapshot
    {
        public DateTime Date { get; set; }
        public DateTime LastUpdated { get; set; }
        public int ProtectionScore { get; set; }
        public int UptimeMinutes { get; set; }

        // Aggregate counts
        public int TotalThreatsBlocked { get; set; }
        public long LinksScanned { get; set; }

        // Phishing / DNS
        public int PhishingDomainsBlocked { get; set; }
        public long DnsQueriesProcessed { get; set; }
        public long DnsQueriesBlocked { get; set; }
        public bool DnsOverTlsActive { get; set; }
        public int DnsBypassAttempts { get; set; }
        public int DomainBlocklistSize { get; set; }
        public int PhishingEventsToday { get; set; }

        // Ransomware
        public int RansomwareThreatsBlocked { get; set; }
        public int VssSnapshotsProtected { get; set; }
        public int ExecutablesHardened { get; set; }

        // Security
        public int SecurityAlertsRaised { get; set; }
        public int ProcessesBlocked { get; set; }
        public int GeoIpConnectionsBlocked { get; set; }
        public int UsbEventsDetected { get; set; }

        // Health
        public int HealthChecksRun { get; set; }
        public int SystemHealthScore { get; set; }

        // Customer Value
        public int BreachedAccountsFound { get; set; }
        public int UnsecureWifiDetected { get; set; }
    }

    #endregion
}
