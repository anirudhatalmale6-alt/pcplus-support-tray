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
        public string SupportPhone { get; set; } = "16047601662";
        public string SupportEmail { get; set; } = "pcpluscomputing@gmail.com";
        public string SupportChatUrl { get; set; } = "";
        public string ChatServerUrl { get; set; } = "";
        public string TicketPortalUrl { get; set; } = "";
        public string ZammadUrl { get; set; } = "https://support.pcpluscomputing.com";
        public string ZammadApiToken { get; set; } = "";
        public string WebsiteUrl { get; set; } = "https://pcpluscomputing.com";
        public string LiveChatUrl { get; set; } = "https://pcpluscomputing51.my3cx.ca/callus/#LiveChat477559";
        public string ForumUrl { get; set; } = "https://forum.pcpluscomputing.com/";
        public string ContactUrl { get; set; } = "https://pcpluscomputing.com/contact-us/";
        public string AppointmentUrl { get; set; } = "https://pcpluscomputing.com/appointments/";
        public string ServiceRequestUrl { get; set; } = "https://pos.pcpluscomputing.com/servicerequests/";
        public bool PersistentOverlay { get; set; } = false;

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
