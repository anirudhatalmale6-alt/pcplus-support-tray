using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using PCPlus.Dashboard.Data;
using PCPlus.Dashboard.Models;

namespace PCPlus.Dashboard.Services
{
    /// <summary>
    /// Generates self-contained HTML security reports for customers.
    /// Extracted from ReportController so it can be reused by EmailReportService and other callers.
    /// Uses IServiceScopeFactory to create its own DI scopes for DashboardDb access.
    /// </summary>
    public class ReportGenerator
    {
        private readonly IServiceScopeFactory _scopeFactory;

        public ReportGenerator(IServiceScopeFactory scopeFactory)
        {
            _scopeFactory = scopeFactory;
        }

        /// <summary>
        /// Generate full HTML report for a customer.
        /// If forEmail=true, strips the action bar and script tags so the HTML is email-safe.
        /// Returns null if no devices found for the customer.
        /// </summary>
        public async Task<string?> GenerateCompanyReportHtml(string customerName, bool forEmail = false)
        {
            using var scope = _scopeFactory.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<DashboardDb>();

            var devices = await db.Devices
                .Where(d => d.CustomerName == customerName)
                .OrderBy(d => d.SecurityScore)
                .ToListAsync();

            if (devices.Count == 0) return null;

            // Parse security checks for each device
            var deviceData = devices.Select(d =>
            {
                var checks = new List<SecurityCheckReport>();
                try
                {
                    if (!string.IsNullOrEmpty(d.SecurityChecksJson) && d.SecurityChecksJson != "[]")
                        checks = JsonSerializer.Deserialize<List<SecurityCheckReport>>(d.SecurityChecksJson,
                            new JsonSerializerOptions { PropertyNameCaseInsensitive = true }) ?? new();
                }
                catch { }
                return new { Device = d, Checks = checks };
            }).ToList();

            // Calculate stats
            int totalDevices = deviceData.Count;
            int online = deviceData.Count(d => d.Device.IsOnline);
            int offline = totalDevices - online;
            int avgScore = totalDevices > 0
                ? (int)Math.Round(deviceData.Average(d => d.Device.SecurityScore))
                : 0;
            int totalChecks = deviceData.Sum(d => d.Checks.Count);
            int totalPassed = deviceData.Sum(d => d.Checks.Count(c => c.Passed));
            int totalFailed = totalChecks - totalPassed;
            int protectedCount = deviceData.Count(d => d.Device.RunningModules > 0);
            int passRate = totalChecks > 0 ? (int)Math.Round(100.0 * totalPassed / totalChecks) : 0;
            string grade = avgScore >= 90 ? "A" : avgScore >= 80 ? "B" : avgScore >= 70 ? "C" : avgScore >= 60 ? "D" : "F";
            string gradeWord = avgScore >= 90 ? "Excellent" : avgScore >= 80 ? "Good" : avgScore >= 70 ? "Fair" : avgScore >= 60 ? "Needs Improvement" : "Critical Attention Required";
            string scoreColor = avgScore >= 80 ? "#16a34a" : avgScore >= 60 ? "#d97706" : "#dc2626";

            // Top issues aggregated across all devices
            var issueMap = new Dictionary<string, (string Name, string Category, string Rec, int Weight, List<string> Devices)>();
            foreach (var dd in deviceData)
                foreach (var c in dd.Checks.Where(c => !c.Passed))
                {
                    if (!issueMap.ContainsKey(c.Id))
                        issueMap[c.Id] = (c.Name, c.Category, c.Recommendation, c.Weight, new List<string>());
                    issueMap[c.Id].Devices.Add(dd.Device.Hostname);
                }
            var topIssues = issueMap.Values.OrderByDescending(i => i.Devices.Count).ThenByDescending(i => i.Weight).ToList();

            // Category breakdown
            var catMap = new Dictionary<string, (int Total, int Passed)>();
            foreach (var dd in deviceData)
                foreach (var c in dd.Checks)
                {
                    var cat = string.IsNullOrEmpty(c.Category) ? "Other" : c.Category;
                    if (!catMap.ContainsKey(cat)) catMap[cat] = (0, 0);
                    var cur = catMap[cat];
                    catMap[cat] = (cur.Total + 1, cur.Passed + (c.Passed ? 1 : 0));
                }
            var catEntries = catMap.OrderBy(kv => (double)kv.Value.Passed / kv.Value.Total).ToList();

            var now = DateTime.Now;
            var reportId = "CR-" + DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString("X");

            // Build HTML
            var sb = new StringBuilder();
            sb.Append("<!DOCTYPE html><html lang=\"en\"><head>");
            sb.Append("<meta charset=\"UTF-8\">");
            sb.Append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">");
            sb.Append($"<title>Security Report - {Esc(customerName)}</title>");
            sb.Append("<style>");
            sb.Append(GetCss());
            sb.Append("</style></head><body>");

            // Action bar (hidden in print; omitted entirely for email)
            if (!forEmail)
            {
                sb.Append(@"<div class=""action-bar no-print"">
                    <button onclick=""window.print()"">Save as PDF</button>
                    <a class=""btn-dl"" id=""dl-btn"">Download HTML</a>
                    <button class=""btn-gray"" onclick=""window.close()"">Close</button>
                </div>");
            }

            // Branded header
            sb.Append($@"<div class=""brand-bar"">
                <div class=""brand-left"">
                    <div class=""brand-shield"">
                        <svg viewBox=""0 0 24 24"" fill=""none"" stroke=""#fff"" stroke-width=""2""><path d=""M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z""/><path d=""M9 12l2 2 4-4"" stroke-linecap=""round"" stroke-linejoin=""round""/></svg>
                    </div>
                    <div class=""brand-text"">
                        <div class=""brand-name"">PC Plus Computing</div>
                        <div class=""brand-tagline"">Your Security. Our Priority. Always Protected.</div>
                    </div>
                </div>
                <div class=""brand-right"">
                    <div class=""date"">{now:MMMM d, yyyy}</div>
                    <div class=""report-id"">Report #{reportId}</div>
                </div>
            </div>");

            // Page 1: Executive Summary
            sb.Append(@"<div class=""cover"">");
            sb.Append($@"<div class=""cover-header"">
                <div class=""customer-name"">{Esc(customerName)}</div>
                <div class=""report-type"">ENDPOINT SECURITY ASSESSMENT</div>
            </div>");

            // Score hero with SVG donut
            sb.Append($@"<div class=""score-hero"">
                <div class=""score-hero-left"">{SvgDonut(avgScore, 100, scoreColor, "#e5e7eb", 140, $"{avgScore}%", $"Grade {grade}")}</div>
                <div class=""score-hero-right"">
                    <div class=""headline"">Security Score: {avgScore}/100 - {gradeWord}</div>
                    <div class=""subline"">Across {totalDevices} managed endpoint{(totalDevices != 1 ? "s" : "")}, {passRate}% of security checks are passing. {totalFailed} issue{(totalFailed != 1 ? "s" : "")} identified that {(totalFailed == 1 ? "requires" : "require")} attention to strengthen your security posture.</div>
                </div>
            </div>");

            // Three small donuts
            sb.Append(@"<div class=""donut-row"">");
            sb.Append($@"<div class=""donut-card"">
                <div class=""label"">Device Status</div>
                {SvgDonut(online, totalDevices, "#22c55e", "#94a3b8", 100, $"{online}/{totalDevices}", "online")}
                <div class=""sub"">{online} online, {offline} offline</div>
            </div>");
            sb.Append($@"<div class=""donut-card"">
                <div class=""label"">Protection</div>
                {SvgDonut(protectedCount, totalDevices, "#22c55e", "#ef4444", 100, $"{protectedCount}/{totalDevices}", "protected")}
                <div class=""sub"">{protectedCount} actively monitored</div>
            </div>");
            sb.Append($@"<div class=""donut-card"">
                <div class=""label"">Checks Passed</div>
                {SvgDonut(totalPassed, totalChecks, "#22c55e", "#ef4444", 100, $"{passRate}%", "pass rate")}
                <div class=""sub"">{totalPassed} passed, {totalFailed} failed</div>
            </div>");
            sb.Append("</div>");

            // Summary boxes
            string gradeColorClass = avgScore >= 80 ? "green" : avgScore >= 60 ? "orange" : "red";
            sb.Append($@"<div class=""summary-row"">
                <div class=""summary-box""><div class=""num blue"">{totalDevices}</div><div class=""lbl"">Endpoints</div></div>
                <div class=""summary-box""><div class=""num green"">{totalPassed}</div><div class=""lbl"">Checks Passed</div></div>
                <div class=""summary-box""><div class=""num red"">{totalFailed}</div><div class=""lbl"">Issues Found</div></div>
                <div class=""summary-box""><div class=""num {gradeColorClass}"">{grade}</div><div class=""lbl"">Security Grade</div></div>
            </div>");

            // Category breakdown
            sb.Append(@"<div class=""section-wrap""><div class=""exec-title"">Security by Category</div><div class=""cat-grid"">");
            var catIcons = new Dictionary<string, string>
            {
                ["Protection"] = "\U0001F6E1", ["Identity & Access"] = "\U0001F511", ["Network"] = "\U0001F310",
                ["Ransomware Protection"] = "\U0001F6A8", ["Updates"] = "\U0001F504", ["Data Protection"] = "\U0001F4BE",
                ["Device Health"] = "\U0001F4BB", ["EDR & Advanced"] = "\U0001F52C", ["Access"] = "\U0001F511",
                ["Logging & Visibility"] = "\U0001F4CB", ["Endpoint Hardening"] = "\U0001F512",
                ["Device Control"] = "\U0001F50C", ["Browser & User Risk"] = "\U0001F310",
                ["Hardware Security"] = "\U0001F527", ["Privilege Escalation"] = "\u26A0"
            };
            foreach (var (cat, data) in catEntries)
            {
                int pct = (int)Math.Round(100.0 * data.Passed / data.Total);
                string color = pct >= 80 ? "#16a34a" : pct >= 60 ? "#d97706" : "#dc2626";
                string icon = catIcons.GetValueOrDefault(cat, "\u2699");
                sb.Append($@"<div class=""cat-row"">
                    <span class=""cat-icon"">{icon}</span>
                    <span class=""cat-name"">{Esc(cat)}</span>
                    <div class=""cat-bar-wrap""><div class=""cat-bar"" style=""width:{pct}%;background:{color}""></div></div>
                    <span class=""cat-pct"" style=""color:{color}"">{pct}%</span>
                </div>");
            }
            sb.Append("</div></div>");

            // Top issues
            sb.Append(@"<div class=""section-wrap""><div class=""exec-title"">Top Issues Requiring Attention</div><div class=""top-issues-grid"">");
            if (topIssues.Count == 0)
                sb.Append(@"<p class=""all-clear"">No critical issues found - great job!</p>");
            else
                foreach (var issue in topIssues.Take(6))
                    sb.Append($@"<div class=""issue-card"">
                        <div class=""issue-name"">{Esc(issue.Name)}</div>
                        <div class=""issue-meta"">{issue.Devices.Count} of {totalDevices} devices | {issue.Weight} pts</div>
                        <div class=""issue-rec"">{Esc(issue.Rec)}</div>
                    </div>");
            sb.Append("</div></div>");

            // Footer for page 1
            sb.Append(@"<div class=""exec-footer"">Prepared by PC Plus Computing | Managed IT Services &amp; Endpoint Security | www.pcpluscomputing.com</div>");
            sb.Append("</div>"); // end cover

            // Page 2: Device table + recommendations
            sb.Append(@"<div class=""detail-section page-break"">
                <div class=""section-title"">Device Security Overview</div>
                <div class=""table-wrap""><table class=""device-table""><thead><tr>
                    <th>Device</th><th>OS</th><th>Grade</th><th>Score</th>
                    <th>Passed</th><th>Failed</th><th>CPU</th><th>RAM</th><th>Disk</th><th>Status</th>
                </tr></thead><tbody>");

            foreach (var dd in deviceData)
            {
                var d = dd.Device;
                int passed = dd.Checks.Count(c => c.Passed);
                int failed = dd.Checks.Count(c => !c.Passed);
                string g = (d.SecurityGrade ?? "F").ToUpper();
                string gc = g switch { "A" => "grade-a", "B" => "grade-b", "C" => "grade-c", "D" => "grade-d", _ => "grade-f" };
                string statusColor = d.IsOnline ? "#16a34a" : "#dc2626";
                sb.Append($@"<tr>
                    <td style=""font-weight:600"">{Esc(d.Hostname)}</td>
                    <td class=""os-col"">{Esc(d.OsVersion)}</td>
                    <td><span class=""grade-badge {gc}"">{g}</span></td>
                    <td style=""font-weight:600"">{d.SecurityScore}/100</td>
                    <td class=""pass"">{passed}</td><td class=""fail"">{failed}</td>
                    <td>{Math.Round(d.CpuPercent)}%</td><td>{Math.Round(d.RamPercent)}%</td><td>{Math.Round(d.DiskPercent)}%</td>
                    <td style=""color:{statusColor};font-weight:600"">{(d.IsOnline ? "Online" : "Offline")}</td>
                </tr>");
            }
            sb.Append("</tbody></table></div>");

            // Priority recommendations
            sb.Append(@"<div class=""section-title"" style=""margin-top:30px"">Priority Recommendations</div>
                <div class=""table-wrap""><table class=""device-table""><thead><tr>
                    <th style=""width:30px"">#</th><th>Issue</th><th>Affected Devices</th><th>Priority</th><th>Recommendation</th>
                </tr></thead><tbody>");
            int recNum = 0;
            foreach (var issue in topIssues.Take(15))
            {
                recNum++;
                string priority = issue.Weight >= 10 ? "<span style=\"color:#dc2626;font-weight:600\">HIGH</span>"
                    : issue.Weight >= 5 ? "<span style=\"color:#d97706;font-weight:600\">MEDIUM</span>"
                    : "<span style=\"color:#666\">LOW</span>";
                sb.Append($@"<tr>
                    <td style=""font-weight:600"">{recNum}</td>
                    <td class=""fail"" style=""font-weight:600"">{Esc(issue.Name)}</td>
                    <td class=""os-col"">{Esc(string.Join(", ", issue.Devices))}</td>
                    <td>{priority}</td>
                    <td style=""font-size:12px"">{Esc(issue.Rec)}</td>
                </tr>");
            }
            sb.Append("</tbody></table></div></div>");

            // Page 3: Per-device breakdown
            sb.Append(@"<div class=""detail-section page-break""><div class=""section-title"">Per-Device Security Breakdown</div>");
            foreach (var dd in deviceData)
            {
                var d = dd.Device;
                var failed = dd.Checks.Where(c => !c.Passed).ToList();
                sb.Append($@"<div class=""device-block"">
                    <div class=""device-block-header"">
                        <span>{Esc(d.Hostname)}{(string.IsNullOrEmpty(d.OsVersion) ? "" : " - " + Esc(d.OsVersion))}</span>
                        <span>Score: {d.SecurityScore}/100 ({d.SecurityGrade?.ToUpper() ?? "?"}) | {failed.Count} issue{(failed.Count != 1 ? "s" : "")}</span>
                    </div>");
                if (failed.Count == 0)
                    sb.Append($@"<div class=""device-all-pass"">All {dd.Checks.Count} security checks passed</div>");
                else
                {
                    sb.Append(@"<table><tr><th>Check</th><th>Category</th><th>Details</th><th style=""width:50px"">Weight</th><th style=""width:120px"">Last Validated</th></tr>");
                    foreach (var c in failed)
                        sb.Append($@"<tr>
                            <td class=""fail"" style=""font-weight:600"">{Esc(c.Name)}</td>
                            <td>{Esc(c.Category)}</td>
                            <td>{Esc(c.Detail)}</td>
                            <td style=""text-align:center;font-weight:600"">{c.Weight}</td>
                            <td style=""font-size:11px;color:#888"">{(c.LastChecked.HasValue ? c.LastChecked.Value.ToString("yyyy-MM-dd HH:mm") : "-")}</td>
                        </tr>");
                    sb.Append("</table>");
                }
                sb.Append("</div>");
            }
            sb.Append("</div>");

            // Footer
            sb.Append(@"<div class=""footer"">
                <p>Prepared by PC Plus Computing - Endpoint Protection Platform</p>
                <p>This report reflects the state of all endpoints at the time of generation.</p>
                <p style=""margin-top:6px;color:#bbb"">www.pcpluscomputing.com | Managed IT Services &amp; Security</p>
            </div>");

            // Minimal JS for download button only (omitted for email)
            if (!forEmail)
            {
                sb.Append(@"<script>
                document.getElementById('dl-btn').addEventListener('click', function() {
                    var html = document.documentElement.outerHTML;
                    var blob = new Blob([html], {type: 'text/html'});
                    var a = document.createElement('a');
                    a.href = URL.createObjectURL(blob);
                    a.download = document.title.replace(/[^a-zA-Z0-9 -]/g,'') + '.html';
                    a.click();
                });
                </script>");
            }

            sb.Append("</body></html>");

            return sb.ToString();
        }

        // --- Helpers ---

        private static string Esc(string? s) => WebUtility.HtmlEncode(s ?? "");

        /// <summary>Generate an SVG donut chart (works in email clients).</summary>
        private static string SvgDonut(int value, int total, string fillColor, string bgColor, int size,
            string centerText, string? centerSub = null)
        {
            double pct = total > 0 ? (double)value / total : 0;
            int r = size / 2 - 14;
            double circ = 2 * Math.PI * r;
            double fillLen = circ * pct;
            double gapLen = circ - fillLen;
            int cx = size / 2, cy = size / 2;
            int strokeW = size > 110 ? 16 : 12;
            int textSize = size > 110 ? 22 : 16;
            int subSize = size > 110 ? 11 : 9;

            var sb = new StringBuilder();
            sb.Append($@"<svg width=""{size}"" height=""{size}"" viewBox=""0 0 {size} {size}"" xmlns=""http://www.w3.org/2000/svg"">");
            // Background circle
            sb.Append($@"<circle cx=""{cx}"" cy=""{cy}"" r=""{r}"" fill=""none"" stroke=""{bgColor}"" stroke-width=""{strokeW}""/>");
            // Fill arc (rotated -90deg to start from top)
            if (pct > 0)
                sb.Append($@"<circle cx=""{cx}"" cy=""{cy}"" r=""{r}"" fill=""none"" stroke=""{fillColor}"" stroke-width=""{strokeW}"" stroke-dasharray=""{fillLen:F1} {gapLen:F1}"" transform=""rotate(-90 {cx} {cy})"" stroke-linecap=""butt""/>");
            // Center text
            int textY = centerSub != null ? cy - 5 : cy + 2;
            sb.Append($@"<text x=""{cx}"" y=""{textY}"" text-anchor=""middle"" dominant-baseline=""middle"" font-family=""Segoe UI,Tahoma,sans-serif"" font-weight=""700"" font-size=""{textSize}"" fill=""#1a1a2e"">{Esc(centerText)}</text>");
            if (centerSub != null)
                sb.Append($@"<text x=""{cx}"" y=""{cy + (size > 110 ? 14 : 10)}"" text-anchor=""middle"" dominant-baseline=""middle"" font-family=""Segoe UI,Tahoma,sans-serif"" font-size=""{subSize}"" fill=""#888"">{Esc(centerSub)}</text>");
            sb.Append("</svg>");
            return sb.ToString();
        }

        private static string GetCss() => @"
            * { margin:0; padding:0; box-sizing:border-box; }
            body { font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif; color:#1a1a2e; background:#fff; }

            .action-bar { padding:14px; text-align:center; background:#f1f5f9; }
            .action-bar button, .action-bar .btn-dl { background:#1a56db; color:#fff; border:none; padding:10px 28px; border-radius:8px; font-size:13px; cursor:pointer; margin:0 4px; display:inline-block; text-decoration:none; }
            .action-bar button:hover, .action-bar .btn-dl:hover { background:#1e40af; }
            .action-bar .btn-gray { background:#6b7280; }

            .brand-bar { background:linear-gradient(135deg,#0f172a,#1e293b); padding:22px 40px; display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:12px; }
            .brand-left { display:flex; align-items:center; gap:14px; }
            .brand-shield { width:44px; height:44px; background:linear-gradient(135deg,#3b82f6,#1d4ed8); border-radius:10px; display:flex; align-items:center; justify-content:center; flex-shrink:0; }
            .brand-shield svg { width:26px; height:26px; }
            .brand-name { color:#fff; font-size:20px; font-weight:700; letter-spacing:-0.3px; }
            .brand-tagline { color:#94a3b8; font-size:11px; font-weight:500; margin-top:2px; letter-spacing:0.5px; }
            .brand-right { text-align:right; }
            .brand-right .date { color:#94a3b8; font-size:12px; }
            .brand-right .report-id { color:#64748b; font-size:10px; margin-top:3px; }

            .cover { padding:36px 40px; }
            .customer-name { font-size:36px; font-weight:800; color:#1a1a2e; line-height:1.1; }
            .report-type { font-size:13px; color:#64748b; font-weight:600; margin-top:4px; text-transform:uppercase; letter-spacing:1.5px; }

            .score-hero { display:flex; align-items:center; gap:30px; padding:24px 30px; background:linear-gradient(135deg,#f8faff,#eef2ff); border-radius:14px; margin:24px 0; flex-wrap:wrap; }
            .score-hero-left { text-align:center; flex-shrink:0; }
            .score-hero-right { flex:1; min-width:200px; }
            .headline { font-size:18px; font-weight:700; margin-bottom:6px; }
            .subline { font-size:13px; color:#666; line-height:1.5; }

            .donut-row { display:flex; justify-content:space-around; align-items:center; margin:24px 0; gap:16px; flex-wrap:wrap; }
            .donut-card { text-align:center; flex:1; min-width:120px; background:#f8f9fa; border-radius:12px; padding:16px 10px; }
            .donut-card .label { font-size:12px; font-weight:600; color:#333; margin-bottom:8px; }
            .donut-card .sub { font-size:11px; color:#666; margin-top:6px; }

            .summary-row { display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin:20px 0; }
            .summary-box { text-align:center; padding:16px 10px; background:#fff; border-radius:12px; border:2px solid #e5e7eb; }
            .summary-box .num { font-size:28px; font-weight:700; }
            .summary-box .lbl { font-size:10px; color:#666; text-transform:uppercase; margin-top:3px; letter-spacing:0.5px; }
            .green { color:#16a34a; } .red { color:#dc2626; } .blue { color:#1a56db; } .orange { color:#d97706; }

            .exec-title { font-size:18px; color:#1a56db; font-weight:700; margin-bottom:14px; padding-bottom:6px; border-bottom:2px solid #e5e7eb; }
            .section-wrap { margin-top:24px; }

            .cat-grid { display:grid; grid-template-columns:1fr 1fr; gap:8px; }
            .cat-row { display:flex; align-items:center; gap:8px; padding:7px 10px; background:#f8fafc; border-radius:8px; }
            .cat-icon { font-size:14px; width:22px; text-align:center; }
            .cat-name { font-size:11px; font-weight:600; color:#334155; width:120px; flex-shrink:0; }
            .cat-bar-wrap { flex:1; height:8px; background:#e5e7eb; border-radius:4px; overflow:hidden; }
            .cat-bar { height:100%; border-radius:4px; }
            .cat-pct { font-size:11px; font-weight:700; width:34px; text-align:right; }

            .top-issues-grid { display:grid; grid-template-columns:1fr 1fr; gap:10px; }
            .issue-card { background:#fff; border:1px solid #fecaca; border-left:4px solid #dc2626; border-radius:8px; padding:12px 14px; }
            .issue-name { font-weight:600; color:#1a1a2e; font-size:12px; }
            .issue-meta { font-size:10px; color:#dc2626; margin-top:2px; font-weight:600; }
            .issue-rec { font-size:11px; color:#666; margin-top:4px; }
            .all-clear { color:#16a34a; font-weight:600; padding:16px; }

            .exec-footer { margin-top:30px; padding-top:20px; text-align:center; color:#aaa; font-size:10px; border-top:1px solid #e5e7eb; }

            .detail-section { padding:36px 40px; }
            .page-break { page-break-before:always; }
            .section-title { font-size:18px; color:#1a56db; font-weight:700; margin-bottom:14px; padding-bottom:6px; border-bottom:2px solid #e5e7eb; }

            .table-wrap { overflow-x:auto; -webkit-overflow-scrolling:touch; }
            .device-table { width:100%; border-collapse:collapse; margin-bottom:20px; min-width:600px; }
            .device-table th { background:#1e293b; color:#fff; text-align:left; padding:8px 10px; font-size:10px; text-transform:uppercase; letter-spacing:0.5px; white-space:nowrap; }
            .device-table td { padding:8px 10px; border-bottom:1px solid #f1f5f9; font-size:12px; }
            .device-table tr:nth-child(even) { background:#f8fafc; }
            .os-col { font-size:10px; color:#666; }
            .pass { color:#16a34a; font-weight:600; } .fail { color:#dc2626; font-weight:600; }

            .grade-badge { display:inline-flex; align-items:center; justify-content:center; width:28px; height:28px; border-radius:50%; color:#fff; font-weight:700; font-size:12px; }
            .grade-a { background:#16a34a; } .grade-b { background:#2563eb; } .grade-c { background:#d97706; } .grade-d { background:#ea580c; } .grade-f { background:#dc2626; }

            .device-block { margin-bottom:20px; border:1px solid #e5e7eb; border-radius:10px; overflow:hidden; }
            .device-block-header { padding:10px 14px; background:#1e293b; color:#fff; font-weight:600; font-size:13px; display:flex; justify-content:space-between; flex-wrap:wrap; gap:6px; }
            .device-block table { width:100%; border-collapse:collapse; }
            .device-block table th { background:#fef3f2; color:#1a1a2e; text-align:left; padding:6px 10px; font-size:10px; text-transform:uppercase; }
            .device-block table td { padding:6px 10px; border-bottom:1px solid #f1f5f9; font-size:11px; }
            .device-all-pass { padding:14px; background:#f0fdf4; color:#16a34a; font-weight:600; text-align:center; font-size:13px; }

            .footer { padding:24px 40px; text-align:center; color:#999; font-size:10px; border-top:2px solid #e5e7eb; }

            /* MOBILE RESPONSIVE */
            @media (max-width:700px) {
                .brand-bar { padding:16px 20px; flex-direction:column; align-items:flex-start; }
                .brand-right { text-align:left; }
                .cover { padding:24px 20px; }
                .customer-name { font-size:26px; }
                .score-hero { flex-direction:column; padding:20px; gap:16px; }
                .score-hero-right { text-align:center; }
                .headline { font-size:16px; }
                .donut-row { flex-direction:column; }
                .donut-card { min-width:auto; }
                .summary-row { grid-template-columns:repeat(2,1fr); }
                .cat-grid { grid-template-columns:1fr; }
                .top-issues-grid { grid-template-columns:1fr; }
                .detail-section { padding:24px 16px; }
                .device-block-header { font-size:11px; }
            }

            @media print {
                .no-print { display:none !important; }
                .cover { min-height:auto; page-break-after:always; }
                .page-break { page-break-before:always; }
                body { -webkit-print-color-adjust:exact; print-color-adjust:exact; }
                .grade-badge,.summary-box,.device-table th,.device-block-header,.score-hero,.donut-card,.brand-bar { -webkit-print-color-adjust:exact; print-color-adjust:exact; }
            }
        ";
    }
}
