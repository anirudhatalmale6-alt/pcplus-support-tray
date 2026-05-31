using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;

namespace SupportTray
{
    public static class SystemInfo
    {
        private static readonly System.Net.Http.HttpClient SharedHttpClient = new()
        {
            Timeout = TimeSpan.FromSeconds(5)
        };

        private static string? _cachedCpu;
        private static string? _cachedOs;

        public static string GetHostname() => Environment.MachineName;

        public static string GetUsername() => Environment.UserName;

        public static string GetOSVersion()
        {
            if (_cachedOs != null) return _cachedOs;
            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT Caption, Version FROM Win32_OperatingSystem");
                using var results = searcher.Get();
                foreach (ManagementObject obj in results)
                {
                    using (obj)
                    {
                        _cachedOs = $"{obj["Caption"]} ({obj["Version"]})";
                        return _cachedOs;
                    }
                }
            }
            catch (Exception ex) { Program.LogError("SystemInfo.GetOSVersion", ex); }
            return RuntimeInformation.OSDescription;
        }

        public static string GetIPAddress()
        {
            try
            {
                var addresses = new List<string>();
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus == OperationalStatus.Up &&
                        ni.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                    {
                        foreach (var addr in ni.GetIPProperties().UnicastAddresses)
                        {
                            if (addr.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                            {
                                addresses.Add(addr.Address.ToString());
                            }
                        }
                    }
                }
                return string.Join(", ", addresses);
            }
            catch { return "Unknown"; }
        }

        public static async System.Threading.Tasks.Task<string> GetPublicIPAsync()
        {
            try
            {
                var result = await SharedHttpClient.GetStringAsync("https://api.ipify.org").ConfigureAwait(false);
                return result.Trim();
            }
            catch { return "Unable to retrieve"; }
        }

        public static string GetCPU()
        {
            if (_cachedCpu != null) return _cachedCpu;
            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT Name FROM Win32_Processor");
                using var results = searcher.Get();
                foreach (ManagementObject obj in results)
                {
                    using (obj)
                    {
                        _cachedCpu = obj["Name"]?.ToString() ?? "Unknown";
                        return _cachedCpu;
                    }
                }
            }
            catch (Exception ex) { Program.LogError("SystemInfo.GetCPU", ex); }
            return "Unknown";
        }

        public static string GetRAM()
        {
            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT TotalPhysicalMemory FROM Win32_ComputerSystem");
                using var results = searcher.Get();
                foreach (ManagementObject obj in results)
                {
                    using (obj)
                    {
                        var bytes = Convert.ToDouble(obj["TotalPhysicalMemory"]);
                        return $"{bytes / (1024 * 1024 * 1024):F1} GB";
                    }
                }
            }
            catch (Exception ex) { Program.LogError("SystemInfo.GetRAM", ex); }
            return "Unknown";
        }

        public static List<(string Name, string Total, string Free, double UsedPercent)> GetDiskInfo()
        {
            var disks = new List<(string, string, string, double)>();
            try
            {
                foreach (var drive in DriveInfo.GetDrives())
                {
                    if (drive.IsReady && drive.DriveType == DriveType.Fixed)
                    {
                        var total = drive.TotalSize / (1024.0 * 1024 * 1024);
                        var free = drive.AvailableFreeSpace / (1024.0 * 1024 * 1024);
                        var usedPct = ((total - free) / total) * 100;
                        disks.Add((drive.Name, $"{total:F1} GB", $"{free:F1} GB", usedPct));
                    }
                }
            }
            catch { }
            return disks;
        }

        public static TimeSpan GetUptime()
        {
            return TimeSpan.FromMilliseconds(Environment.TickCount64);
        }

        public static string GetTacticalAgentId()
        {
            try
            {
                // Tactical RMM agent stores its ID in the registry
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\TacticalRMM");
                if (key != null)
                {
                    return key.GetValue("AgentID")?.ToString() ?? "";
                }
            }
            catch { }

            // Also check the agent config file
            try
            {
                var configPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                    "TacticalAgent", "agent.json");
                if (File.Exists(configPath))
                {
                    var json = File.ReadAllText(configPath);
                    var doc = System.Text.Json.JsonDocument.Parse(json);
                    if (doc.RootElement.TryGetProperty("agentid", out var agentId))
                        return agentId.GetString() ?? "";
                }
            }
            catch { }

            return "";
        }

        public static async System.Threading.Tasks.Task<string> GetFullReportAsync()
        {
            var publicIpTask = GetPublicIPAsync();

            var sb = new StringBuilder();
            sb.AppendLine($"Computer Name: {GetHostname()}");
            sb.AppendLine($"Username: {GetUsername()}");
            sb.AppendLine($"Operating System: {GetOSVersion()}");
            sb.AppendLine($"CPU: {GetCPU()}");
            sb.AppendLine($"RAM: {GetRAM()}");
            sb.AppendLine($"Local IP: {GetIPAddress()}");
            sb.AppendLine($"Public IP: {await publicIpTask.ConfigureAwait(false)}");

            var uptime = GetUptime();
            sb.AppendLine($"Uptime: {uptime.Days}d {uptime.Hours}h {uptime.Minutes}m");

            sb.AppendLine();
            sb.AppendLine("--- Disk Information ---");
            foreach (var disk in GetDiskInfo())
            {
                sb.AppendLine($"  {disk.Name}  Total: {disk.Total}  Free: {disk.Free}  Used: {disk.UsedPercent:F0}%");
            }

            var agentId = GetTacticalAgentId();
            if (!string.IsNullOrEmpty(agentId))
            {
                sb.AppendLine();
                sb.AppendLine($"Tactical RMM Agent ID: {agentId}");
            }

            return sb.ToString();
        }
    }
}
