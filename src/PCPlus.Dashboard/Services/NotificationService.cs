using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using PCPlus.Dashboard.Data;

namespace PCPlus.Dashboard.Services
{
    /// <summary>
    /// Singleton service that dispatches notifications (webhook, Slack, Teams)
    /// based on notification configs stored in the database.
    /// </summary>
    public class NotificationService
    {
        private readonly IServiceScopeFactory _scopeFactory;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly ILogger<NotificationService> _log;

        private static readonly Dictionary<string, int> SeverityRank = new(StringComparer.OrdinalIgnoreCase)
        {
            ["Info"] = 0,
            ["Warning"] = 1,
            ["Critical"] = 2,
            ["Emergency"] = 3
        };

        public NotificationService(
            IServiceScopeFactory scopeFactory,
            IHttpClientFactory httpClientFactory,
            ILogger<NotificationService> log)
        {
            _scopeFactory = scopeFactory;
            _httpClientFactory = httpClientFactory;
            _log = log;
        }

        /// <summary>
        /// Send a notification to all enabled configs whose minimum severity is met.
        /// </summary>
        public async Task SendNotificationAsync(string title, string message, string severity, string deviceId, string hostname)
        {
            List<NotificationConfig> configs;
            try
            {
                using var scope = _scopeFactory.CreateScope();
                var db = scope.ServiceProvider.GetRequiredService<DashboardDb>();
                configs = await db.Set<NotificationConfig>()
                    .Where(c => c.Enabled)
                    .ToListAsync();
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "Failed to load notification configs from database");
                return;
            }

            var eventRank = SeverityRank.GetValueOrDefault(severity, 0);

            foreach (var config in configs)
            {
                var minRank = SeverityRank.GetValueOrDefault(config.MinSeverity, 2);
                if (eventRank < minRank)
                    continue;

                try
                {
                    switch (config.Type.ToLowerInvariant())
                    {
                        case "webhook":
                            await SendWebhookAsync(config, title, message, severity, deviceId, hostname);
                            break;
                        case "slack":
                            await SendSlackAsync(config, title, message, severity, deviceId, hostname);
                            break;
                        case "teams":
                            await SendTeamsAsync(config, title, message, severity, deviceId, hostname);
                            break;
                        default:
                            _log.LogWarning("Unknown notification type '{Type}' for config '{Name}'", config.Type, config.Name);
                            break;
                    }
                }
                catch (Exception ex)
                {
                    _log.LogError(ex, "Failed to send {Type} notification '{Name}' to {Url}",
                        config.Type, config.Name, config.WebhookUrl);
                }
            }
        }

        private async Task SendWebhookAsync(NotificationConfig config, string title, string message, string severity, string deviceId, string hostname)
        {
            var client = _httpClientFactory.CreateClient();
            var payload = new
            {
                title,
                message,
                severity,
                deviceId,
                hostname,
                timestamp = DateTime.UtcNow.ToString("o")
            };

            var response = await client.PostAsJsonAsync(config.WebhookUrl, payload);
            _log.LogInformation("Webhook '{Name}' responded {StatusCode}", config.Name, response.StatusCode);
        }

        private async Task SendSlackAsync(NotificationConfig config, string title, string message, string severity, string deviceId, string hostname)
        {
            var client = _httpClientFactory.CreateClient();
            var emoji = severity switch
            {
                "Emergency" => ":rotating_light:",
                "Critical" => ":red_circle:",
                "Warning" => ":warning:",
                _ => ":information_source:"
            };

            var payload = new
            {
                blocks = new object[]
                {
                    new
                    {
                        type = "header",
                        text = new { type = "plain_text", text = $"{emoji} {title}" }
                    },
                    new
                    {
                        type = "section",
                        fields = new object[]
                        {
                            new { type = "mrkdwn", text = $"*Severity:*\n{severity}" },
                            new { type = "mrkdwn", text = $"*Device:*\n{hostname} ({deviceId})" }
                        }
                    },
                    new
                    {
                        type = "section",
                        text = new { type = "mrkdwn", text = message }
                    }
                }
            };

            var response = await client.PostAsJsonAsync(config.WebhookUrl, payload);
            _log.LogInformation("Slack '{Name}' responded {StatusCode}", config.Name, response.StatusCode);
        }

        private async Task SendTeamsAsync(NotificationConfig config, string title, string message, string severity, string deviceId, string hostname)
        {
            var client = _httpClientFactory.CreateClient();
            var color = severity switch
            {
                "Emergency" => "attention",
                "Critical" => "attention",
                "Warning" => "warning",
                _ => "default"
            };

            var payload = new
            {
                type = "message",
                attachments = new object[]
                {
                    new
                    {
                        contentType = "application/vnd.microsoft.card.adaptive",
                        content = new
                        {
                            type = "AdaptiveCard",
                            version = "1.4",
                            body = new object[]
                            {
                                new
                                {
                                    type = "TextBlock",
                                    text = title,
                                    weight = "Bolder",
                                    size = "Medium",
                                    color
                                },
                                new
                                {
                                    type = "FactSet",
                                    facts = new object[]
                                    {
                                        new { title = "Severity", value = severity },
                                        new { title = "Device", value = hostname },
                                        new { title = "Device ID", value = deviceId },
                                        new { title = "Time", value = DateTime.UtcNow.ToString("o") }
                                    }
                                },
                                new
                                {
                                    type = "TextBlock",
                                    text = message,
                                    wrap = true
                                }
                            }
                        }
                    }
                }
            };

            var response = await client.PostAsJsonAsync(config.WebhookUrl, payload);
            _log.LogInformation("Teams '{Name}' responded {StatusCode}", config.Name, response.StatusCode);
        }
    }

    /// <summary>
    /// Notification configuration entity stored in the database.
    /// </summary>
    public class NotificationConfig
    {
        [System.ComponentModel.DataAnnotations.Key]
        public int Id { get; set; }
        public string Name { get; set; } = "";
        public string Type { get; set; } = "webhook"; // webhook, slack, teams
        public string WebhookUrl { get; set; } = "";
        public string MinSeverity { get; set; } = "Critical"; // Info, Warning, Critical, Emergency
        public bool Enabled { get; set; } = true;
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    }
}
