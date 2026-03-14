using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace SupportTray
{
    public class TacticalRmmApi
    {
        private readonly HttpClient _client;
        private readonly string _baseUrl;
        private readonly string _apiKey;

        public TacticalRmmApi(string baseUrl, string apiKey)
        {
            _baseUrl = baseUrl.TrimEnd('/');
            _apiKey = apiKey;
            _client = new HttpClient();
            _client.DefaultRequestHeaders.Add("X-API-KEY", _apiKey);
            _client.Timeout = TimeSpan.FromSeconds(30);
        }

        public async Task<(bool Success, string Message, int? TicketId)> CreateTicketAsync(
            string subject, string description, string agentId = "")
        {
            try
            {
                var payload = new
                {
                    subject = subject,
                    description = description,
                    priority = "normal",
                    agent_id = string.IsNullOrEmpty(agentId) ? null : agentId
                };

                var json = JsonSerializer.Serialize(payload);
                var content = new StringContent(json, Encoding.UTF8, "application/json");

                var response = await _client.PostAsync($"{_baseUrl}/api/v3/tickets/", content);
                var responseBody = await response.Content.ReadAsStringAsync();

                if (response.IsSuccessStatusCode)
                {
                    try
                    {
                        var doc = JsonDocument.Parse(responseBody);
                        int? ticketId = null;
                        if (doc.RootElement.TryGetProperty("id", out var idProp))
                            ticketId = idProp.GetInt32();
                        return (true, "Ticket created successfully!", ticketId);
                    }
                    catch
                    {
                        return (true, "Ticket created successfully!", null);
                    }
                }
                else
                {
                    return (false, $"Server returned: {response.StatusCode}", null);
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

        public async Task<bool> TestConnectionAsync()
        {
            try
            {
                var response = await _client.GetAsync($"{_baseUrl}/api/v3/agents/");
                return response.IsSuccessStatusCode;
            }
            catch
            {
                return false;
            }
        }
    }
}
