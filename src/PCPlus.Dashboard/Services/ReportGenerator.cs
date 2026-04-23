using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using PCPlus.Dashboard.Data;
using PCPlus.Dashboard.Models;

namespace PCPlus.Dashboard.Services
{
    public class ReportGenerator
    {
        private readonly IServiceScopeFactory _scopeFactory;

        public ReportGenerator(IServiceScopeFactory scopeFactory)
        {
            _scopeFactory = scopeFactory;
        }

        public async Task<string?> GenerateCompanyReportHtml(string customerName, bool forEmail = false)
        {
            using var scope = _scopeFactory.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<DashboardDb>();

            var devices = await db.Devices
                .Where(d => d.CustomerName == customerName)
                .OrderBy(d => d.SecurityScore)
                .ToListAsync();

            if (devices.Count == 0) return null;

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

            var issueMap = new Dictionary<string, (string Name, string Category, string Rec, int Weight, List<string> Devices)>();
            foreach (var dd in deviceData)
                foreach (var c in dd.Checks.Where(c => !c.Passed))
                {
                    if (!issueMap.ContainsKey(c.Id))
                        issueMap[c.Id] = (c.Name, c.Category, c.Recommendation, c.Weight, new List<string>());
                    issueMap[c.Id].Devices.Add(dd.Device.Hostname);
                }
            var topIssues = issueMap.Values.OrderByDescending(i => i.Devices.Count).ThenByDescending(i => i.Weight).ToList();

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

            var catIcons = new Dictionary<string, string>
            {
                ["Protection"] = "\U0001F6E1", ["Identity & Access"] = "\U0001F511", ["Network"] = "\U0001F310",
                ["Ransomware Protection"] = "\U0001F6A8", ["Updates"] = "\U0001F504", ["Data Protection"] = "\U0001F4BE",
                ["Device Health"] = "\U0001F4BB", ["EDR & Advanced"] = "\U0001F52C", ["Access"] = "\U0001F511",
                ["Logging & Visibility"] = "\U0001F4CB", ["Endpoint Hardening"] = "\U0001F512",
                ["Device Control"] = "\U0001F50C", ["Browser & User Risk"] = "\U0001F310",
                ["Hardware Security"] = "\U0001F527", ["Privilege Escalation"] = "⚠",
                ["RMM Stack"] = "\U0001F4E1"
            };

            var now = DateTime.Now;
            var reportId = "CR-" + DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString("X");

            var sb = new StringBuilder();
            sb.Append("<!DOCTYPE html><html lang=\"en\"><head>");
            sb.Append("<meta charset=\"UTF-8\">");
            sb.Append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">");
            sb.Append($"<title>Security Report - {Esc(customerName)}</title>");
            sb.Append("<style>");
            sb.Append(GetCss());
            sb.Append("</style></head><body>");

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

            // ==================================================================
            // EXECUTIVE SUMMARY - Slide 1: At A Glance
            // ==================================================================
            string statusLabel = avgScore >= 80 ? "PROTECTED" : avgScore >= 60 ? "AT RISK" : "CRITICAL";
            string statusBg = avgScore >= 80 ? "linear-gradient(135deg,#dcfce7,#f0fdf4)" : avgScore >= 60 ? "linear-gradient(135deg,#fef3c7,#fffbeb)" : "linear-gradient(135deg,#fee2e2,#fef2f2)";
            string statusBorder = avgScore >= 80 ? "#16a34a" : avgScore >= 60 ? "#d97706" : "#dc2626";
            string statusIcon = avgScore >= 80
                ? @"<svg viewBox=""0 0 24 24"" width=""36"" height=""36"" fill=""none"" stroke=""#16a34a"" stroke-width=""2""><path d=""M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z""/><path d=""M9 12l2 2 4-4""/></svg>"
                : avgScore >= 60
                ? @"<svg viewBox=""0 0 24 24"" width=""36"" height=""36"" fill=""none"" stroke=""#d97706"" stroke-width=""2""><path d=""M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z""/><line x1=""12"" y1=""9"" x2=""12"" y2=""13""/><line x1=""12"" y1=""17"" x2=""12.01"" y2=""17""/></svg>"
                : @"<svg viewBox=""0 0 24 24"" width=""36"" height=""36"" fill=""none"" stroke=""#dc2626"" stroke-width=""2""><polygon points=""7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2""/><line x1=""15"" y1=""9"" x2=""9"" y2=""15""/><line x1=""9"" y1=""9"" x2=""15"" y2=""15""/></svg>";

            sb.Append(@"<div class=""exec-slide"">");
            sb.Append($@"<div class=""cover-header"">
                <div class=""customer-name"">{Esc(customerName)}</div>
                <div class=""report-type"">SECURITY POSTURE REPORT</div>
                <div class=""report-timestamp"">Generated: {now:MMMM d, yyyy} at {now:h:mm tt}</div>
            </div>");

            sb.Append($@"<div class=""exec-status-banner"" style=""background:{statusBg};border-color:{statusBorder}"">
                <div class=""exec-status-left"">
                    <div class=""exec-status-icon"">{statusIcon}</div>
                    <div>
                        <div class=""exec-status-label"" style=""color:{statusBorder}"">{statusLabel}</div>
                        <div class=""exec-status-sub"">Overall Security Status</div>
                    </div>
                </div>
                <div class=""exec-status-score"">
                    {SvgDonut(avgScore, 100, scoreColor, "#e5e7eb", 120, $"{avgScore}%", $"Grade {grade}")}
                </div>
            </div>");

            string gradeColorClass = avgScore >= 80 ? "green" : avgScore >= 60 ? "orange" : "red";
            int highIssues = topIssues.Count(i => i.Weight >= 10);
            int medIssues = topIssues.Count(i => i.Weight >= 5 && i.Weight < 10);

            sb.Append($@"<div class=""exec-metrics"">
                <div class=""exec-metric-card"">
                    <div class=""exec-metric-icon"" style=""background:linear-gradient(135deg,#3b82f6,#1d4ed8)"">
                        <svg viewBox=""0 0 24 24"" fill=""none"" stroke=""#fff"" stroke-width=""2"" width=""28"" height=""28""><rect x=""2"" y=""3"" width=""20"" height=""14"" rx=""2""/><line x1=""8"" y1=""21"" x2=""16"" y2=""21""/><line x1=""12"" y1=""17"" x2=""12"" y2=""21""/></svg>
                    </div>
                    <div class=""exec-metric-num blue"">{totalDevices}</div>
                    <div class=""exec-metric-label"">Endpoints Managed</div>
                    <div class=""exec-metric-detail"">{online} online, {offline} offline</div>
                </div>
                <div class=""exec-metric-card"">
                    <div class=""exec-metric-icon"" style=""background:linear-gradient(135deg,#22c55e,#16a34a)"">
                        <svg viewBox=""0 0 24 24"" fill=""none"" stroke=""#fff"" stroke-width=""2"" width=""28"" height=""28""><path d=""M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z""/><path d=""M9 12l2 2 4-4""/></svg>
                    </div>
                    <div class=""exec-metric-num green"">{totalPassed}</div>
                    <div class=""exec-metric-label"">Checks Passed</div>
                    <div class=""exec-metric-detail"">out of {totalChecks} total checks</div>
                </div>
                <div class=""exec-metric-card"">
                    <div class=""exec-metric-icon"" style=""background:linear-gradient(135deg,#ef4444,#dc2626)"">
                        <svg viewBox=""0 0 24 24"" fill=""none"" stroke=""#fff"" stroke-width=""2"" width=""28"" height=""28""><circle cx=""12"" cy=""12"" r=""10""/><line x1=""15"" y1=""9"" x2=""9"" y2=""15""/><line x1=""9"" y1=""9"" x2=""15"" y2=""15""/></svg>
                    </div>
                    <div class=""exec-metric-num red"">{totalFailed}</div>
                    <div class=""exec-metric-label"">Issues Found</div>
                    <div class=""exec-metric-detail"">{highIssues} high, {medIssues} medium priority</div>
                </div>
                <div class=""exec-metric-card"">
                    <div class=""exec-metric-icon"" style=""background:linear-gradient(135deg,#8b5cf6,#7c3aed)"">
                        <svg viewBox=""0 0 24 24"" fill=""none"" stroke=""#fff"" stroke-width=""2"" width=""28"" height=""28""><path d=""M22 12h-4l-3 9L9 3l-3 9H2""/></svg>
                    </div>
                    <div class=""exec-metric-num {gradeColorClass}"">{grade}</div>
                    <div class=""exec-metric-label"">Security Grade</div>
                    <div class=""exec-metric-detail"">{gradeWord}</div>
                </div>
            </div>");

            var worstCats = catEntries.Where(kv => (double)kv.Value.Passed / kv.Value.Total < 0.6).Select(kv => kv.Key).Take(3).ToList();
            var bestCats = catEntries.Where(kv => (double)kv.Value.Passed / kv.Value.Total >= 0.8).Select(kv => kv.Key).Take(3).ToList();

            sb.Append(@"<div class=""exec-summary-box"">
                <div class=""exec-summary-title"">Summary</div>
                <div class=""exec-summary-bullets"">");
            sb.Append($@"<div class=""exec-bullet"">
                <span class=""exec-bullet-dot"" style=""background:#3b82f6""></span>
                <span>We scanned <strong>{totalDevices} endpoint{(totalDevices != 1 ? "s" : "")}</strong> with <strong>120 security checks</strong> each, covering protection, updates, network security, ransomware defense, and more.</span>
            </div>");
            if (totalFailed > 0)
                sb.Append($@"<div class=""exec-bullet"">
                    <span class=""exec-bullet-dot"" style=""background:#dc2626""></span>
                    <span><strong>{totalFailed} issue{(totalFailed != 1 ? "s" : "")} detected</strong> across your environment. {(highIssues > 0 ? $"<strong>{highIssues}</strong> are high priority and should be addressed promptly." : "Most are medium or low priority.")}</span>
                </div>");
            if (worstCats.Count > 0)
                sb.Append($@"<div class=""exec-bullet"">
                    <span class=""exec-bullet-dot"" style=""background:#d97706""></span>
                    <span>Areas needing the most attention: <strong>{Esc(string.Join(", ", worstCats))}</strong></span>
                </div>");
            if (bestCats.Count > 0)
                sb.Append($@"<div class=""exec-bullet"">
                    <span class=""exec-bullet-dot"" style=""background:#16a34a""></span>
                    <span>Strong performance in: <strong>{Esc(string.Join(", ", bestCats))}</strong></span>
                </div>");
            sb.Append("</div></div>");

            sb.Append(@"<div class=""exec-footer"">Prepared by PC Plus Computing | Managed IT Services &amp; Endpoint Security | www.pcpluscomputing.com</div>");
            sb.Append("</div>");

            // ==================================================================
            // EXECUTIVE SUMMARY - Slide 2: Key Findings & Risk Areas
            // ==================================================================
            sb.Append(@"<div class=""exec-slide page-break"">");
            sb.Append(@"<div class=""exec-slide-title"">Key Findings</div>");

            var passedHighWeight = deviceData.SelectMany(d => d.Checks).Where(c => c.Passed && c.Weight >= 5)
                .GroupBy(c => c.Name).OrderByDescending(g => g.First().Weight).Take(5).ToList();
            var failedHighWeight = topIssues.Where(i => i.Weight >= 5).Take(5).ToList();

            sb.Append(@"<div class=""exec-findings-grid"">");
            sb.Append(@"<div class=""exec-findings-col"">
                <div class=""exec-findings-header"" style=""background:linear-gradient(135deg,#22c55e,#16a34a)"">
                    <svg viewBox=""0 0 24 24"" fill=""none"" stroke=""#fff"" stroke-width=""2"" width=""20"" height=""20""><path d=""M22 11.08V12a10 10 0 11-5.93-9.14""/><polyline points=""22 4 12 14.01 9 11.01""/></svg>
                    What's Working Well
                </div>
                <div class=""exec-findings-body"">");
            if (passedHighWeight.Count > 0)
                foreach (var g in passedHighWeight)
                    sb.Append($@"<div class=""exec-finding-item"">
                        <span class=""exec-finding-icon pass"">&#10003;</span>
                        <div>
                            <div class=""exec-finding-name"">{Esc(g.First().Name)}</div>
                            <div class=""exec-finding-detail"">Passing on {g.Count()} of {totalDevices} device{(totalDevices != 1 ? "s" : "")}</div>
                        </div>
                    </div>");
            else
                sb.Append(@"<div style=""padding:16px;color:#666;text-align:center"">Run a scan to populate results</div>");
            sb.Append("</div></div>");

            sb.Append(@"<div class=""exec-findings-col"">
                <div class=""exec-findings-header"" style=""background:linear-gradient(135deg,#ef4444,#dc2626)"">
                    <svg viewBox=""0 0 24 24"" fill=""none"" stroke=""#fff"" stroke-width=""2"" width=""20"" height=""20""><circle cx=""12"" cy=""12"" r=""10""/><line x1=""15"" y1=""9"" x2=""9"" y2=""15""/><line x1=""9"" y1=""9"" x2=""15"" y2=""15""/></svg>
                    What Needs Attention
                </div>
                <div class=""exec-findings-body"">");
            if (failedHighWeight.Count > 0)
                foreach (var issue in failedHighWeight)
                {
                    string prioColor = issue.Weight >= 10 ? "#dc2626" : "#d97706";
                    string prioLabel = issue.Weight >= 10 ? "HIGH" : "MEDIUM";
                    sb.Append($@"<div class=""exec-finding-item"">
                        <span class=""exec-finding-icon fail"">&#10007;</span>
                        <div>
                            <div class=""exec-finding-name"">{Esc(issue.Name)} <span class=""exec-prio-tag"" style=""background:{prioColor}"">{prioLabel}</span></div>
                            <div class=""exec-finding-detail"">Failing on {issue.Devices.Count} of {totalDevices} device{(totalDevices != 1 ? "s" : "")}</div>
                        </div>
                    </div>");
                }
            else
                sb.Append(@"<div style=""padding:16px;color:#16a34a;text-align:center;font-weight:600"">No critical issues found!</div>");
            sb.Append("</div></div>");
            sb.Append("</div>");

            sb.Append(@"<div class=""exec-cat-section"">
                <div class=""exec-slide-title"" style=""margin-top:24px"">Security Health by Category</div>
                <div class=""exec-cat-grid"">");
            foreach (var (cat, data) in catEntries)
            {
                int pct = (int)Math.Round(100.0 * data.Passed / data.Total);
                string color = pct >= 80 ? "#16a34a" : pct >= 60 ? "#d97706" : "#dc2626";
                string icon = catIcons.GetValueOrDefault(cat, "⚙");
                string statusTag = pct >= 80 ? "Good" : pct >= 60 ? "Fair" : "Needs Work";
                sb.Append($@"<div class=""exec-cat-card"">
                    <div class=""exec-cat-top"">
                        <span class=""cat-icon"">{icon}</span>
                        <span class=""exec-cat-name"">{Esc(cat)}</span>
                        <span class=""exec-cat-tag"" style=""background:{color}"">{statusTag}</span>
                    </div>
                    <div class=""exec-cat-bar-wrap""><div class=""exec-cat-bar"" style=""width:{pct}%;background:{color}""></div></div>
                    <div class=""exec-cat-stat"">{data.Passed}/{data.Total} checks passing</div>
                </div>");
            }
            sb.Append("</div></div>");

            sb.Append(@"<div class=""exec-footer"">Prepared by PC Plus Computing | Managed IT Services &amp; Endpoint Security | www.pcpluscomputing.com</div>");
            sb.Append("</div>");

            // ==================================================================
            // EXECUTIVE SUMMARY - Slide 3: Recommended Actions
            // ==================================================================
            sb.Append(@"<div class=""exec-slide page-break"">");
            sb.Append(@"<div class=""exec-slide-title"">Recommended Next Steps</div>");

            var quickWins = topIssues.Where(i => i.Weight <= 5).Take(4).ToList();
            var strategic = topIssues.Where(i => i.Weight >= 8).Take(4).ToList();

            sb.Append(@"<div class=""exec-actions-grid"">");
            sb.Append(@"<div class=""exec-action-col"">
                <div class=""exec-action-header"" style=""background:linear-gradient(135deg,#22c55e,#16a34a)"">
                    <svg viewBox=""0 0 24 24"" fill=""none"" stroke=""#fff"" stroke-width=""2"" width=""22"" height=""22""><path d=""M13 2L3 14h9l-1 8 10-12h-9l1-8z""/></svg>
                    Quick Wins
                </div>
                <div class=""exec-action-desc"">Can be fixed remotely with minimal disruption</div>
                <div class=""exec-action-list"">");
            if (quickWins.Count > 0)
            {
                int qn = 0;
                foreach (var qw in quickWins)
                {
                    qn++;
                    sb.Append($@"<div class=""exec-action-item"">
                        <div class=""exec-action-num"">{qn}</div>
                        <div>
                            <div class=""exec-action-name"">{Esc(qw.Name)}</div>
                            <div class=""exec-action-impact"">{qw.Devices.Count} device{(qw.Devices.Count != 1 ? "s" : "")} affected</div>
                        </div>
                    </div>");
                }
            }
            else
                sb.Append(@"<div style=""padding:12px;color:#16a34a;font-weight:600"">All quick wins addressed!</div>");
            sb.Append("</div></div>");

            sb.Append(@"<div class=""exec-action-col"">
                <div class=""exec-action-header"" style=""background:linear-gradient(135deg,#3b82f6,#1d4ed8)"">
                    <svg viewBox=""0 0 24 24"" fill=""none"" stroke=""#fff"" stroke-width=""2"" width=""22"" height=""22""><circle cx=""12"" cy=""12"" r=""10""/><path d=""M12 6v6l4 2""/></svg>
                    Strategic Improvements
                </div>
                <div class=""exec-action-desc"">High-impact changes for stronger security posture</div>
                <div class=""exec-action-list"">");
            if (strategic.Count > 0)
            {
                int sn = 0;
                foreach (var si in strategic)
                {
                    sn++;
                    sb.Append($@"<div class=""exec-action-item"">
                        <div class=""exec-action-num"" style=""background:#1d4ed8"">{sn}</div>
                        <div>
                            <div class=""exec-action-name"">{Esc(si.Name)}</div>
                            <div class=""exec-action-impact"">{si.Devices.Count} device{(si.Devices.Count != 1 ? "s" : "")} | {si.Weight} pts impact</div>
                        </div>
                    </div>");
                }
            }
            else
                sb.Append(@"<div style=""padding:12px;color:#16a34a;font-weight:600"">Excellent security posture!</div>");
            sb.Append("</div></div>");
            sb.Append("</div>");

            sb.Append($@"<div class=""exec-cta"">
                <div class=""exec-cta-title"">Let's Strengthen Your Security</div>
                <div class=""exec-cta-text"">PC Plus Computing can address {(totalFailed > 10 ? "many of " : "")}these findings through our managed security services. Contact us to discuss a remediation plan tailored to your business.</div>
                <div class=""exec-cta-contact"">www.pcpluscomputing.com</div>
            </div>");

            sb.Append(@"<div class=""exec-footer"">Prepared by PC Plus Computing | Managed IT Services &amp; Endpoint Security | www.pcpluscomputing.com</div>");
            sb.Append("</div>");

            // ==================================================================
            // DETAILED REPORT - Original data pages
            // ==================================================================

            // Page 4: Donuts + top issues
            sb.Append(@"<div class=""cover page-break"">");
            sb.Append(@"<div class=""exec-title"" style=""font-size:22px;margin-bottom:20px"">Detailed Assessment Data</div>");

            sb.Append($@"<div class=""score-hero"">
                <div class=""score-hero-left"">{SvgDonut(avgScore, 100, scoreColor, "#e5e7eb", 140, $"{avgScore}%", $"Grade {grade}")}</div>
                <div class=""score-hero-right"">
                    <div class=""headline"">Security Score: {avgScore}/100 - {gradeWord}</div>
                    <div class=""subline"">Across {totalDevices} managed endpoint{(totalDevices != 1 ? "s" : "")}, {passRate}% of security checks are passing. {totalFailed} issue{(totalFailed != 1 ? "s" : "")} identified that {(totalFailed == 1 ? "requires" : "require")} attention to strengthen your security posture.</div>
                </div>
            </div>");

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

            sb.Append($@"<div class=""summary-row"">
                <div class=""summary-box""><div class=""num blue"">{totalDevices}</div><div class=""lbl"">Endpoints</div></div>
                <div class=""summary-box""><div class=""num green"">{totalPassed}</div><div class=""lbl"">Checks Passed</div></div>
                <div class=""summary-box""><div class=""num red"">{totalFailed}</div><div class=""lbl"">Issues Found</div></div>
                <div class=""summary-box""><div class=""num {gradeColorClass}"">{grade}</div><div class=""lbl"">Security Grade</div></div>
            </div>");

            sb.Append(@"<div class=""section-wrap""><div class=""exec-title"">Security by Category</div><div class=""cat-grid"">");
            foreach (var (cat, data) in catEntries)
            {
                int pct = (int)Math.Round(100.0 * data.Passed / data.Total);
                string color = pct >= 80 ? "#16a34a" : pct >= 60 ? "#d97706" : "#dc2626";
                string icon = catIcons.GetValueOrDefault(cat, "⚙");
                sb.Append($@"<div class=""cat-row"">
                    <span class=""cat-icon"">{icon}</span>
                    <span class=""cat-name"">{Esc(cat)}</span>
                    <div class=""cat-bar-wrap""><div class=""cat-bar"" style=""width:{pct}%;background:{color}""></div></div>
                    <span class=""cat-pct"" style=""color:{color}"">{pct}%</span>
                </div>");
            }
            sb.Append("</div></div>");

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
            sb.Append(@"<div class=""exec-footer"">Prepared by PC Plus Computing | Managed IT Services &amp; Endpoint Security | www.pcpluscomputing.com</div>");
            sb.Append("</div>");

            // Device table + recommendations
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

            // Per-device breakdown
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

            sb.Append(@"<div class=""footer"">
                <p>Prepared by PC Plus Computing - Endpoint Protection Platform</p>
                <p>This report reflects the state of all endpoints at the time of generation.</p>
                <p style=""margin-top:6px;color:#bbb"">www.pcpluscomputing.com | Managed IT Services &amp; Security</p>
            </div>");

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

        private static string Esc(string? s) => WebUtility.HtmlEncode(s ?? "");

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
            sb.Append($@"<circle cx=""{cx}"" cy=""{cy}"" r=""{r}"" fill=""none"" stroke=""{bgColor}"" stroke-width=""{strokeW}""/>");
            if (pct > 0)
                sb.Append($@"<circle cx=""{cx}"" cy=""{cy}"" r=""{r}"" fill=""none"" stroke=""{fillColor}"" stroke-width=""{strokeW}"" stroke-dasharray=""{fillLen:F1} {gapLen:F1}"" transform=""rotate(-90 {cx} {cy})"" stroke-linecap=""butt""/>");
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

            /* EXECUTIVE SUMMARY STYLES */
            .exec-slide { padding:36px 40px; }
            .exec-slide-title { font-size:22px; color:#1a56db; font-weight:800; margin-bottom:18px; padding-bottom:8px; border-bottom:3px solid #1a56db; }

            .exec-status-banner { display:flex; align-items:center; justify-content:space-between; padding:24px 30px; border-radius:16px; border:2px solid; margin:20px 0; flex-wrap:wrap; gap:16px; }
            .exec-status-left { display:flex; align-items:center; gap:16px; }
            .exec-status-icon { flex-shrink:0; }
            .exec-status-label { font-size:28px; font-weight:800; letter-spacing:2px; }
            .exec-status-sub { font-size:13px; color:#666; margin-top:2px; }
            .exec-status-score { flex-shrink:0; }

            .exec-metrics { display:grid; grid-template-columns:repeat(4,1fr); gap:16px; margin:24px 0; }
            .exec-metric-card { text-align:center; padding:20px 12px 16px; background:#fff; border-radius:16px; border:1px solid #e5e7eb; box-shadow:0 2px 8px rgba(0,0,0,0.04); }
            .exec-metric-icon { width:52px; height:52px; border-radius:14px; display:flex; align-items:center; justify-content:center; margin:0 auto 12px; }
            .exec-metric-num { font-size:36px; font-weight:800; line-height:1; }
            .exec-metric-label { font-size:11px; font-weight:700; color:#334155; text-transform:uppercase; letter-spacing:0.5px; margin-top:6px; }
            .exec-metric-detail { font-size:11px; color:#94a3b8; margin-top:4px; }

            .exec-summary-box { margin:24px 0; padding:24px 28px; background:#f8fafc; border-radius:14px; border:1px solid #e2e8f0; }
            .exec-summary-title { font-size:16px; font-weight:700; color:#1a56db; margin-bottom:14px; }
            .exec-summary-bullets { display:flex; flex-direction:column; gap:12px; }
            .exec-bullet { display:flex; align-items:flex-start; gap:12px; font-size:14px; line-height:1.6; color:#334155; }
            .exec-bullet-dot { width:10px; height:10px; border-radius:50%; flex-shrink:0; margin-top:6px; }

            .exec-findings-grid { display:grid; grid-template-columns:1fr 1fr; gap:20px; }
            .exec-findings-col { border-radius:14px; overflow:hidden; border:1px solid #e5e7eb; background:#fff; }
            .exec-findings-header { color:#fff; font-weight:700; font-size:14px; padding:14px 18px; display:flex; align-items:center; gap:10px; }
            .exec-findings-body { padding:6px 0; }
            .exec-finding-item { display:flex; align-items:flex-start; gap:12px; padding:10px 18px; border-bottom:1px solid #f1f5f9; }
            .exec-finding-item:last-child { border-bottom:none; }
            .exec-finding-icon { font-size:16px; flex-shrink:0; margin-top:1px; }
            .exec-finding-icon.pass { color:#16a34a; }
            .exec-finding-icon.fail { color:#dc2626; }
            .exec-finding-name { font-size:13px; font-weight:600; color:#1a1a2e; }
            .exec-finding-detail { font-size:11px; color:#94a3b8; margin-top:2px; }
            .exec-prio-tag { font-size:9px; padding:1px 6px; border-radius:8px; color:#fff; font-weight:600; vertical-align:middle; }

            .exec-cat-section { margin-top:8px; }
            .exec-cat-grid { display:grid; grid-template-columns:1fr 1fr; gap:10px; }
            .exec-cat-card { padding:12px 16px; background:#f8fafc; border-radius:10px; border:1px solid #e5e7eb; }
            .exec-cat-top { display:flex; align-items:center; gap:8px; margin-bottom:8px; }
            .exec-cat-name { font-size:12px; font-weight:600; color:#334155; flex:1; }
            .exec-cat-tag { font-size:9px; padding:2px 8px; border-radius:10px; color:#fff; font-weight:700; text-transform:uppercase; letter-spacing:0.3px; }
            .exec-cat-bar-wrap { height:8px; background:#e5e7eb; border-radius:4px; overflow:hidden; }
            .exec-cat-bar { height:100%; border-radius:4px; transition:width 0.3s; }
            .exec-cat-stat { font-size:10px; color:#94a3b8; margin-top:4px; }

            .exec-actions-grid { display:grid; grid-template-columns:1fr 1fr; gap:20px; margin-bottom:24px; }
            .exec-action-col { border-radius:14px; overflow:hidden; border:1px solid #e5e7eb; background:#fff; }
            .exec-action-header { color:#fff; font-weight:700; font-size:15px; padding:16px 20px; display:flex; align-items:center; gap:10px; }
            .exec-action-desc { padding:10px 20px 0; font-size:12px; color:#94a3b8; }
            .exec-action-list { padding:8px 12px 12px; }
            .exec-action-item { display:flex; align-items:center; gap:12px; padding:10px 8px; border-bottom:1px solid #f1f5f9; }
            .exec-action-item:last-child { border-bottom:none; }
            .exec-action-num { width:28px; height:28px; border-radius:50%; background:#16a34a; color:#fff; display:flex; align-items:center; justify-content:center; font-weight:700; font-size:12px; flex-shrink:0; }
            .exec-action-name { font-size:13px; font-weight:600; color:#1a1a2e; }
            .exec-action-impact { font-size:11px; color:#94a3b8; margin-top:1px; }

            .exec-cta { text-align:center; padding:30px 40px; margin:8px 0 20px; background:linear-gradient(135deg,#0f172a,#1e293b); border-radius:16px; color:#fff; }
            .exec-cta-title { font-size:22px; font-weight:800; margin-bottom:10px; }
            .exec-cta-text { font-size:14px; color:#cbd5e1; line-height:1.6; max-width:600px; margin:0 auto 14px; }
            .exec-cta-contact { font-size:13px; color:#3b82f6; font-weight:600; }

            /* ORIGINAL DETAIL STYLES */
            .cover { padding:36px 40px; }
            .customer-name { font-size:36px; font-weight:800; color:#1a1a2e; line-height:1.1; }
            .report-type { font-size:13px; color:#64748b; font-weight:600; margin-top:4px; text-transform:uppercase; letter-spacing:1.5px; }
            .report-timestamp { font-size:12px; color:#94a3b8; margin-top:6px; font-weight:500; }

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

            @media (max-width:700px) {
                .brand-bar { padding:16px 20px; flex-direction:column; align-items:flex-start; }
                .brand-right { text-align:left; }
                .cover, .exec-slide { padding:24px 20px; }
                .customer-name { font-size:26px; }
                .exec-status-banner { flex-direction:column; text-align:center; }
                .exec-status-label { font-size:22px; }
                .exec-metrics { grid-template-columns:repeat(2,1fr); }
                .exec-findings-grid { grid-template-columns:1fr; }
                .exec-cat-grid { grid-template-columns:1fr; }
                .exec-actions-grid { grid-template-columns:1fr; }
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
                .exec-slide { page-break-after:always; }
                .cover { min-height:auto; page-break-after:always; }
                .page-break { page-break-before:always; }
                body { -webkit-print-color-adjust:exact; print-color-adjust:exact; }
                .grade-badge,.summary-box,.device-table th,.device-block-header,.score-hero,.donut-card,.brand-bar,.exec-status-banner,.exec-metric-card,.exec-findings-header,.exec-action-header,.exec-cta,.exec-cat-tag,.exec-action-num,.exec-prio-tag { -webkit-print-color-adjust:exact; print-color-adjust:exact; }
            }
        ";
    }
}
