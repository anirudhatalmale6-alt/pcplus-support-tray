using System.Drawing;
using System.Management;
using System.Windows.Forms;
using PCPlus.Core.IPC;
using PCPlus.Core.Models;

namespace PCPlus.Tray.Forms
{
    /// <summary>
    /// System Information - shows hardware details, OS, network info.
    /// </summary>
    public class SystemInfoForm : Form
    {
        private readonly IpcClient _ipc;
        private static readonly Color BgDark = Color.FromArgb(18, 18, 24);
        private static readonly Color BgCard = Color.FromArgb(28, 28, 40);
        private static readonly Color TextPrimary = Color.FromArgb(230, 230, 240);
        private static readonly Color TextSecondary = Color.FromArgb(140, 140, 160);
        private static readonly Color AccentBlue = Color.FromArgb(60, 130, 246);
        private static readonly Color Border = Color.FromArgb(45, 45, 60);

        private ListView _infoList = null!;

        public SystemInfoForm(IpcClient ipc)
        {
            _ipc = ipc;
            InitializeForm();
            BuildUI();
            _ = LoadInfo();
        }

        private void InitializeForm()
        {
            Text = "PC Plus - System Information";
            Size = new Size(600, 520);
            StartPosition = FormStartPosition.CenterScreen;
            BackColor = BgDark;
            ForeColor = TextPrimary;
            FormBorderStyle = FormBorderStyle.FixedSingle;
            MaximizeBox = false;
            Font = new Font("Segoe UI", 9.5f);
        }

        private void BuildUI()
        {
            var header = new Panel { Dock = DockStyle.Top, Height = 55, BackColor = BgCard };
            var title = new Label
            {
                Text = "System Information", AutoSize = true,
                Font = new Font("Segoe UI", 14, FontStyle.Bold),
                ForeColor = TextPrimary, Location = new Point(16, 12)
            };
            var copyBtn = new Button
            {
                Text = "Copy All", Size = new Size(80, 32),
                FlatStyle = FlatStyle.Flat, BackColor = AccentBlue,
                ForeColor = Color.White, Font = new Font("Segoe UI", 9),
                Cursor = Cursors.Hand, Location = new Point(490, 10)
            };
            copyBtn.FlatAppearance.BorderSize = 0;
            copyBtn.Click += (s, e) =>
            {
                var text = "";
                foreach (ListViewItem item in _infoList.Items)
                    text += $"{item.Text}: {item.SubItems[1].Text}\n";
                if (!string.IsNullOrEmpty(text))
                {
                    Clipboard.SetText(text);
                    copyBtn.Text = "Copied!";
                    _ = Task.Delay(1500).ContinueWith(_ =>
                    {
                        if (!IsDisposed) Invoke(new Action(() => copyBtn.Text = "Copy All"));
                    });
                }
            };
            header.Controls.AddRange(new Control[] { title, copyBtn });

            _infoList = new ListView
            {
                Dock = DockStyle.Fill, View = View.Details,
                BackColor = BgDark, ForeColor = TextPrimary,
                Font = new Font("Segoe UI", 9.5f),
                FullRowSelect = true, HeaderStyle = ColumnHeaderStyle.Nonclickable,
                BorderStyle = BorderStyle.None, GridLines = false
            };
            _infoList.Columns.Add("Property", 200);
            _infoList.Columns.Add("Value", 370);

            Controls.Add(_infoList);
            Controls.Add(header);
        }

        private async Task LoadInfo()
        {
            var items = new List<(string category, string key, string value)>();

            // OS Info
            items.Add(("System", "Computer Name", Environment.MachineName));
            items.Add(("System", "User", $"{Environment.UserDomainName}\\{Environment.UserName}"));
            items.Add(("System", "OS", GetFriendlyOsVersion()));
            items.Add(("System", "Architecture", Environment.Is64BitOperatingSystem ? "64-bit" : "32-bit"));
            items.Add(("System", ".NET Runtime", System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription));

            // Hardware via WMI (run off UI thread)
            var hwInfo = await Task.Run(() => GetHardwareInfo());
            items.AddRange(hwInfo);

            // Health data from service
            try
            {
                var response = await Task.Run(() => _ipc.GetHealthSnapshotAsync());
                if (response.Success)
                {
                    var health = response.GetData<HealthSnapshot>();
                    if (health != null)
                    {
                        items.Add(("Health", "CPU Usage", $"{health.CpuPercent:F0}%"));
                        items.Add(("Health", "RAM Usage", $"{health.RamUsedGB:F1} / {health.RamTotalGB:F1} GB ({health.RamPercent:F0}%)"));
                        items.Add(("Health", "CPU Temperature", health.CpuTempC > 0 ? $"{health.CpuTempC:F0}°C" : "N/A"));
                        items.Add(("Health", "GPU Temperature", health.GpuTempC > 0 ? $"{health.GpuTempC:F0}°C" : "N/A"));
                        items.Add(("Health", "Uptime", $"{(int)health.Uptime.TotalDays}d {health.Uptime.Hours}h {health.Uptime.Minutes}m"));
                        items.Add(("Health", "Processes", health.ProcessCount.ToString()));
                        items.Add(("Health", "Network", $"Up: {health.NetworkSentKBps:F0} KB/s  Down: {health.NetworkRecvKBps:F0} KB/s"));

                        foreach (var disk in health.Disks)
                            items.Add(("Disks", $"Drive {disk.Name}", $"{disk.FreeGB:F0} GB free / {disk.TotalGB:F0} GB ({disk.UsedPercent:F0}% used)"));
                    }
                }
            }
            catch { }

            // Display
            if (InvokeRequired)
                Invoke(new Action(() => PopulateList(items)));
            else
                PopulateList(items);
        }

        private void PopulateList(List<(string category, string key, string value)> items)
        {
            _infoList.Items.Clear();
            string lastCategory = "";

            foreach (var (category, key, value) in items)
            {
                if (category != lastCategory)
                {
                    var catItem = new ListViewItem(new[] { $"--- {category} ---", "" })
                    {
                        ForeColor = AccentBlue,
                        Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
                        BackColor = BgCard
                    };
                    _infoList.Items.Add(catItem);
                    lastCategory = category;
                }

                var item = new ListViewItem(new[] { key, value })
                {
                    ForeColor = TextPrimary
                };
                item.SubItems[1].ForeColor = TextSecondary;
                _infoList.Items.Add(item);
            }
        }

        private static List<(string, string, string)> GetHardwareInfo()
        {
            var items = new List<(string, string, string)>();
            try
            {
                // CPU
                using var cpuSearch = new ManagementObjectSearcher("SELECT Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed FROM Win32_Processor");
                foreach (var obj in cpuSearch.Get())
                {
                    items.Add(("Hardware", "CPU", obj["Name"]?.ToString()?.Trim() ?? "Unknown"));
                    items.Add(("Hardware", "Cores / Threads", $"{obj["NumberOfCores"]} / {obj["NumberOfLogicalProcessors"]}"));
                    items.Add(("Hardware", "Max Clock", $"{obj["MaxClockSpeed"]} MHz"));
                }

                // RAM
                using var ramSearch = new ManagementObjectSearcher("SELECT TotalPhysicalMemory FROM Win32_ComputerSystem");
                foreach (var obj in ramSearch.Get())
                {
                    var totalBytes = Convert.ToInt64(obj["TotalPhysicalMemory"]);
                    items.Add(("Hardware", "Total RAM", $"{totalBytes / 1024 / 1024 / 1024.0:F1} GB"));
                }

                // GPU
                using var gpuSearch = new ManagementObjectSearcher("SELECT Name, AdapterRAM FROM Win32_VideoController");
                foreach (var obj in gpuSearch.Get())
                {
                    var vram = Convert.ToInt64(obj["AdapterRAM"] ?? 0);
                    var vramStr = vram > 0 ? $" ({vram / 1024 / 1024} MB)" : "";
                    items.Add(("Hardware", "GPU", $"{obj["Name"]}{vramStr}"));
                }

                // Motherboard
                using var mbSearch = new ManagementObjectSearcher("SELECT Manufacturer, Product FROM Win32_BaseBoard");
                foreach (var obj in mbSearch.Get())
                    items.Add(("Hardware", "Motherboard", $"{obj["Manufacturer"]} {obj["Product"]}"));

                // BIOS
                using var biosSearch = new ManagementObjectSearcher("SELECT SMBIOSBIOSVersion, ReleaseDate FROM Win32_BIOS");
                foreach (var obj in biosSearch.Get())
                    items.Add(("Hardware", "BIOS", obj["SMBIOSBIOSVersion"]?.ToString() ?? "Unknown"));

                // Network adapters
                using var netSearch = new ManagementObjectSearcher(
                    "SELECT Description, MACAddress, Speed FROM Win32_NetworkAdapter WHERE NetEnabled=True AND PhysicalAdapter=True");
                foreach (var obj in netSearch.Get())
                {
                    var speed = Convert.ToInt64(obj["Speed"] ?? 0);
                    var speedStr = speed > 0 ? $" ({speed / 1000000} Mbps)" : "";
                    items.Add(("Network", obj["Description"]?.ToString() ?? "Adapter", $"MAC: {obj["MACAddress"]}{speedStr}"));
                }
            }
            catch { }
            return items;
        }

        private static string GetFriendlyOsVersion()
        {
            var ver = Environment.OSVersion.Version;
            string name = ver.Major == 10 && ver.Build >= 22000 ? "Windows 11" :
                ver.Major == 10 ? "Windows 10" : $"Windows {ver.Major}.{ver.Minor}";
            return $"{name} (Build {ver.Build})";
        }
    }
}
