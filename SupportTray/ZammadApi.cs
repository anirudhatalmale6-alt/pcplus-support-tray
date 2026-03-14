using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace SupportTray
{
    public class ZammadApi
    {
        private readonly HttpClient _client;
        private readonly string _baseUrl;

        public ZammadApi(string baseUrl, string apiToken)
        {
            _baseUrl = baseUrl.TrimEnd('/');
            _client = new HttpClient();
            _client.DefaultRequestHeaders.Authorization =
                new AuthenticationHeaderValue("Token", apiToken);
            _client.Timeout = TimeSpan.FromSeconds(30);
        }

        public async Task<(bool Success, string Message, int? TicketId)> CreateTicketAsync(
            string subject, string description, string customerEmail, string? screenshotPath = null)
        {
            try
            {
                var articleBody = description.Replace("\n", "<br>");

                var payload = new Dictionary<string, object>
                {
                    ["title"] = subject,
                    ["group"] = "Users",
                    ["customer"] = customerEmail,
                    ["article"] = new Dictionary<string, object>
                    {
                        ["subject"] = subject,
                        ["body"] = articleBody,
                        ["type"] = "note",
                        ["internal"] = false,
                        ["content_type"] = "text/html"
                    }
                };

                var json = JsonSerializer.Serialize(payload);
                var content = new StringContent(json, Encoding.UTF8, "application/json");

                var response = await _client.PostAsync($"{_baseUrl}/api/v1/tickets", content);
                var responseBody = await response.Content.ReadAsStringAsync();

                if (response.IsSuccessStatusCode)
                {
                    var doc = JsonDocument.Parse(responseBody);
                    int? ticketId = null;
                    string? ticketNumber = null;

                    if (doc.RootElement.TryGetProperty("id", out var idProp))
                        ticketId = idProp.GetInt32();
                    if (doc.RootElement.TryGetProperty("number", out var numProp))
                        ticketNumber = numProp.GetString();

                    // Upload screenshot as attachment if provided
                    if (ticketId.HasValue && !string.IsNullOrEmpty(screenshotPath) && File.Exists(screenshotPath))
                    {
                        await AddAttachmentAsync(ticketId.Value, screenshotPath);
                    }

                    var ticketRef = ticketNumber ?? ticketId?.ToString() ?? "";
                    return (true, $"Ticket #{ticketRef} created successfully!", ticketId);
                }
                else
                {
                    return (false, $"Server returned: {response.StatusCode} - {responseBody}", null);
                }
            }
            catch (HttpRequestException ex)
            {
                return (false, $"Connection error: {ex.Message}", null);
            }
            catch (TaskCanceledException)
            {
                return (false, "Request timed out. Please try again.", null);
            }
            catch (Exception ex)
            {
                return (false, $"Error: {ex.Message}", null);
            }
        }

        public async Task<bool> AddAttachmentAsync(int ticketId, string filePath)
        {
            try
            {
                var fileBytes = File.ReadAllBytes(filePath);
                var base64 = Convert.ToBase64String(fileBytes);
                var fileName = Path.GetFileName(filePath);
                var mimeType = GetMimeType(fileName);

                var payload = new Dictionary<string, object>
                {
                    ["ticket_id"] = ticketId,
                    ["body"] = $"<p>Attachment: {fileName}</p>",
                    ["content_type"] = "text/html",
                    ["type"] = "note",
                    ["internal"] = false,
                    ["attachments"] = new[]
                    {
                        new Dictionary<string, string>
                        {
                            ["filename"] = fileName,
                            ["data"] = base64,
                            ["mime-type"] = mimeType
                        }
                    }
                };

                var json = JsonSerializer.Serialize(payload);
                var content = new StringContent(json, Encoding.UTF8, "application/json");
                var response = await _client.PostAsync($"{_baseUrl}/api/v1/ticket_articles", content);
                return response.IsSuccessStatusCode;
            }
            catch
            {
                return false;
            }
        }

        public async Task<(bool Success, string Message, int? ArticleId)> AddMessageAsync(
            int ticketId, string message, string? attachmentPath = null)
        {
            try
            {
                var payload = new Dictionary<string, object>
                {
                    ["ticket_id"] = ticketId,
                    ["body"] = message.Replace("\n", "<br>"),
                    ["content_type"] = "text/html",
                    ["type"] = "note",
                    ["internal"] = false
                };

                if (!string.IsNullOrEmpty(attachmentPath) && File.Exists(attachmentPath))
                {
                    var fileBytes = File.ReadAllBytes(attachmentPath);
                    var base64 = Convert.ToBase64String(fileBytes);
                    var fileName = Path.GetFileName(attachmentPath);
                    payload["attachments"] = new[]
                    {
                        new Dictionary<string, string>
                        {
                            ["filename"] = fileName,
                            ["data"] = base64,
                            ["mime-type"] = GetMimeType(fileName)
                        }
                    };
                }

                var json = JsonSerializer.Serialize(payload);
                var content = new StringContent(json, Encoding.UTF8, "application/json");
                var response = await _client.PostAsync($"{_baseUrl}/api/v1/ticket_articles", content);
                var responseBody = await response.Content.ReadAsStringAsync();

                if (response.IsSuccessStatusCode)
                {
                    var doc = JsonDocument.Parse(responseBody);
                    int? articleId = null;
                    if (doc.RootElement.TryGetProperty("id", out var idProp))
                        articleId = idProp.GetInt32();
                    return (true, "Message sent!", articleId);
                }
                return (false, $"Error: {response.StatusCode}", null);
            }
            catch (Exception ex)
            {
                return (false, $"Error: {ex.Message}", null);
            }
        }

        public async Task<List<TicketArticle>> GetTicketArticlesAsync(int ticketId)
        {
            var articles = new List<TicketArticle>();
            try
            {
                var response = await _client.GetAsync($"{_baseUrl}/api/v1/ticket_articles/by_ticket/{ticketId}");
                if (response.IsSuccessStatusCode)
                {
                    var json = await response.Content.ReadAsStringAsync();
                    var arr = JsonDocument.Parse(json).RootElement;
                    foreach (var el in arr.EnumerateArray())
                    {
                        articles.Add(new TicketArticle
                        {
                            Id = el.GetProperty("id").GetInt32(),
                            Body = el.TryGetProperty("body", out var b) ? StripHtml(b.GetString() ?? "") : "",
                            Sender = el.TryGetProperty("sender", out var s) ? s.GetString() ?? "" :
                                     el.TryGetProperty("sender_id", out var sid) ? (sid.GetInt32() == 1 ? "Agent" : "Customer") : "Unknown",
                            CreatedAt = el.TryGetProperty("created_at", out var ca) ? ca.GetString() ?? "" : "",
                            From = el.TryGetProperty("from", out var f) ? f.GetString() ?? "" : ""
                        });
                    }
                }
            }
            catch { }
            return articles;
        }

        public async Task<List<TicketSummary>> GetMyTicketsAsync()
        {
            var tickets = new List<TicketSummary>();
            try
            {
                var response = await _client.GetAsync($"{_baseUrl}/api/v1/tickets/search?query=state.name:open OR state.name:new&limit=20&sort_by=updated_at&order_by=desc");
                if (response.IsSuccessStatusCode)
                {
                    var json = await response.Content.ReadAsStringAsync();
                    var doc = JsonDocument.Parse(json);

                    if (doc.RootElement.TryGetProperty("assets", out var assets) &&
                        assets.TryGetProperty("Ticket", out var ticketsObj))
                    {
                        foreach (var prop in ticketsObj.EnumerateObject())
                        {
                            var t = prop.Value;
                            tickets.Add(new TicketSummary
                            {
                                Id = t.GetProperty("id").GetInt32(),
                                Number = t.TryGetProperty("number", out var n) ? n.GetString() ?? "" : "",
                                Title = t.TryGetProperty("title", out var title) ? title.GetString() ?? "" : "",
                                State = t.TryGetProperty("state_id", out var st) ? GetStateName(st.GetInt32()) : "open",
                                UpdatedAt = t.TryGetProperty("updated_at", out var ua) ? ua.GetString() ?? "" : ""
                            });
                        }
                    }
                }
            }
            catch { }
            return tickets;
        }

        public async Task<bool> TestConnectionAsync()
        {
            try
            {
                var response = await _client.GetAsync($"{_baseUrl}/api/v1/users/me");
                return response.IsSuccessStatusCode;
            }
            catch
            {
                return false;
            }
        }

        private static string GetStateName(int stateId)
        {
            return stateId switch
            {
                1 => "new",
                2 => "open",
                3 => "pending",
                4 => "closed",
                _ => "open"
            };
        }

        private static string GetMimeType(string fileName)
        {
            var ext = Path.GetExtension(fileName).ToLowerInvariant();
            return ext switch
            {
                ".png" => "image/png",
                ".jpg" or ".jpeg" => "image/jpeg",
                ".gif" => "image/gif",
                ".bmp" => "image/bmp",
                ".webp" => "image/webp",
                ".pdf" => "application/pdf",
                ".txt" => "text/plain",
                ".log" => "text/plain",
                ".zip" => "application/zip",
                _ => "application/octet-stream"
            };
        }

        private static string StripHtml(string html)
        {
            // Simple HTML tag removal for display
            var result = System.Text.RegularExpressions.Regex.Replace(html, "<[^>]+>", "");
            result = result.Replace("&nbsp;", " ").Replace("&amp;", "&")
                          .Replace("&lt;", "<").Replace("&gt;", ">")
                          .Replace("&quot;", "\"");
            return result.Trim();
        }
    }

    public class TicketArticle
    {
        public int Id { get; set; }
        public string Body { get; set; } = "";
        public string Sender { get; set; } = "";
        public string CreatedAt { get; set; } = "";
        public string From { get; set; } = "";
    }

    public class TicketSummary
    {
        public int Id { get; set; }
        public string Number { get; set; } = "";
        public string Title { get; set; } = "";
        public string State { get; set; } = "";
        public string UpdatedAt { get; set; } = "";
    }
}
