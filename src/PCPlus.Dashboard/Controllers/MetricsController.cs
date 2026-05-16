using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using PCPlus.Dashboard.Data;

namespace PCPlus.Dashboard.Controllers
{
    [ApiController]
    [Route("metrics")]
    public class MetricsController : ControllerBase
    {
        private readonly DashboardDb _db;

        public MetricsController(DashboardDb db)
        {
            _db = db;
        }

        [HttpGet]
        public async Task<IActionResult> GetMetrics()
        {
            var sb = new StringBuilder();

            var devices = await _db.Devices.ToListAsync();
            var alerts = await _db.Alerts
                .Where(a => a.Timestamp > DateTime.UtcNow.AddHours(-24))
                .ToListAsync();

            // Fleet overview
            sb.AppendLine("# HELP pcplus_devices_total Total number of registered devices");
            sb.AppendLine("# TYPE pcplus_devices_total gauge");
            sb.AppendLine($"pcplus_devices_total {devices.Count}");

            sb.AppendLine("# HELP pcplus_devices_online Number of devices currently online");
            sb.AppendLine("# TYPE pcplus_devices_online gauge");
            sb.AppendLine($"pcplus_devices_online {devices.Count(d => d.IsOnline)}");

            sb.AppendLine("# HELP pcplus_devices_offline Number of devices currently offline");
            sb.AppendLine("# TYPE pcplus_devices_offline gauge");
            sb.AppendLine($"pcplus_devices_offline {devices.Count(d => !d.IsOnline)}");

            // Per-device metrics
            sb.AppendLine("# HELP pcplus_device_cpu_percent CPU usage percentage");
            sb.AppendLine("# TYPE pcplus_device_cpu_percent gauge");
            foreach (var d in devices)
                sb.AppendLine($"pcplus_device_cpu_percent{{device=\"{Escape(d.Hostname)}\",customer=\"{Escape(d.CustomerName)}\"}} {d.CpuPercent:F1}");

            sb.AppendLine("# HELP pcplus_device_ram_percent RAM usage percentage");
            sb.AppendLine("# TYPE pcplus_device_ram_percent gauge");
            foreach (var d in devices)
                sb.AppendLine($"pcplus_device_ram_percent{{device=\"{Escape(d.Hostname)}\",customer=\"{Escape(d.CustomerName)}\"}} {d.RamPercent:F1}");

            sb.AppendLine("# HELP pcplus_device_disk_percent Disk usage percentage");
            sb.AppendLine("# TYPE pcplus_device_disk_percent gauge");
            foreach (var d in devices)
                sb.AppendLine($"pcplus_device_disk_percent{{device=\"{Escape(d.Hostname)}\",customer=\"{Escape(d.CustomerName)}\"}} {d.DiskPercent:F1}");

            sb.AppendLine("# HELP pcplus_device_cpu_temp_celsius CPU temperature");
            sb.AppendLine("# TYPE pcplus_device_cpu_temp_celsius gauge");
            foreach (var d in devices.Where(d => d.CpuTempC > 0))
                sb.AppendLine($"pcplus_device_cpu_temp_celsius{{device=\"{Escape(d.Hostname)}\"}} {d.CpuTempC:F1}");

            sb.AppendLine("# HELP pcplus_device_security_score Security score 0-100");
            sb.AppendLine("# TYPE pcplus_device_security_score gauge");
            foreach (var d in devices)
                sb.AppendLine($"pcplus_device_security_score{{device=\"{Escape(d.Hostname)}\",customer=\"{Escape(d.CustomerName)}\",grade=\"{Escape(d.SecurityGrade)}\"}} {d.SecurityScore}");

            sb.AppendLine("# HELP pcplus_device_online Device online status (1=online, 0=offline)");
            sb.AppendLine("# TYPE pcplus_device_online gauge");
            foreach (var d in devices)
                sb.AppendLine($"pcplus_device_online{{device=\"{Escape(d.Hostname)}\",customer=\"{Escape(d.CustomerName)}\"}} {(d.IsOnline ? 1 : 0)}");

            // Alert metrics
            sb.AppendLine("# HELP pcplus_alerts_24h_total Total alerts in last 24 hours");
            sb.AppendLine("# TYPE pcplus_alerts_24h_total gauge");
            sb.AppendLine($"pcplus_alerts_24h_total {alerts.Count}");

            sb.AppendLine("# HELP pcplus_alerts_by_severity Alerts by severity in last 24h");
            sb.AppendLine("# TYPE pcplus_alerts_by_severity gauge");
            foreach (var g in alerts.GroupBy(a => a.Severity))
                sb.AppendLine($"pcplus_alerts_by_severity{{severity=\"{g.Key}\"}} {g.Count()}");

            sb.AppendLine("# HELP pcplus_alerts_unacknowledged Unacknowledged alerts");
            sb.AppendLine("# TYPE pcplus_alerts_unacknowledged gauge");
            sb.AppendLine($"pcplus_alerts_unacknowledged {alerts.Count(a => !a.Acknowledged)}");

            // License tier breakdown
            sb.AppendLine("# HELP pcplus_devices_by_tier Devices by license tier");
            sb.AppendLine("# TYPE pcplus_devices_by_tier gauge");
            foreach (var g in devices.GroupBy(d => d.LicenseTier))
                sb.AppendLine($"pcplus_devices_by_tier{{tier=\"{Escape(g.Key)}\"}} {g.Count()}");

            // Average fleet health
            if (devices.Any())
            {
                sb.AppendLine("# HELP pcplus_fleet_avg_security_score Average security score across fleet");
                sb.AppendLine("# TYPE pcplus_fleet_avg_security_score gauge");
                sb.AppendLine($"pcplus_fleet_avg_security_score {devices.Average(d => d.SecurityScore):F1}");

                sb.AppendLine("# HELP pcplus_fleet_avg_cpu Average CPU usage across fleet");
                sb.AppendLine("# TYPE pcplus_fleet_avg_cpu gauge");
                sb.AppendLine($"pcplus_fleet_avg_cpu {devices.Average(d => d.CpuPercent):F1}");

                sb.AppendLine("# HELP pcplus_fleet_avg_ram Average RAM usage across fleet");
                sb.AppendLine("# TYPE pcplus_fleet_avg_ram gauge");
                sb.AppendLine($"pcplus_fleet_avg_ram {devices.Average(d => d.RamPercent):F1}");

                sb.AppendLine("# HELP pcplus_fleet_avg_disk Average disk usage across fleet");
                sb.AppendLine("# TYPE pcplus_fleet_avg_disk gauge");
                sb.AppendLine($"pcplus_fleet_avg_disk {devices.Average(d => d.DiskPercent):F1}");
            }

            return Content(sb.ToString(), "text/plain; version=0.0.4; charset=utf-8");
        }

        private static string Escape(string value)
        {
            if (string.IsNullOrEmpty(value)) return "";
            return value.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\n", "\\n");
        }
    }
}
