using System;
using System.IO;
using System.Text.Json;

namespace SupportTray
{
    public class AppConfig
    {
        public string CompanyName { get; set; } = "PC Plus Computing";
        public string RmmUrl { get; set; } = "https://rmm.pcpluscomputing.com";
        public string RmmApiKey { get; set; } = "";
        public string SupportPhone { get; set; } = "";
        public string SupportEmail { get; set; } = "";
        public string SupportChatUrl { get; set; } = "";
        public string TicketPortalUrl { get; set; } = "";

        private static readonly string ConfigDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "PCPlusSupport");
        private static readonly string ConfigFile = Path.Combine(ConfigDir, "config.json");

        public static AppConfig Load()
        {
            try
            {
                if (File.Exists(ConfigFile))
                {
                    var json = File.ReadAllText(ConfigFile);
                    return JsonSerializer.Deserialize<AppConfig>(json) ?? new AppConfig();
                }
            }
            catch { }
            return new AppConfig();
        }

        public void Save()
        {
            try
            {
                Directory.CreateDirectory(ConfigDir);
                var json = JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(ConfigFile, json);
            }
            catch { }
        }
    }
}
