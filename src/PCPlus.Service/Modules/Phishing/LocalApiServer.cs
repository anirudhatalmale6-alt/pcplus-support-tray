using System.Net;
using System.Text;
using System.Text.Json;
using PCPlus.Core.Interfaces;

namespace PCPlus.Service.Modules.Phishing
{
    public class LocalApiServer : IDisposable
    {
        private const string ModuleName = "local-api";
        private const int ApiPort = 9876;

        private HttpListener? _listener;
        private CancellationTokenSource? _cts;
        private Task? _listenTask;
        private IModuleContext _context = null!;
        private Func<string, object>? _checkUrl;
        private Func<string[], object>? _checkUrls;
        private bool _isActive;

        public void Start(IModuleContext context,
            Func<string, object> checkUrl,
            Func<string[], object> checkUrls)
        {
            _context = context;
            _checkUrl = checkUrl;
            _checkUrls = checkUrls;
            _cts = new CancellationTokenSource();

            try
            {
                _listener = new HttpListener();
                _listener.Prefixes.Add($"http://127.0.0.1:{ApiPort}/");
                _listener.Start();
                _listenTask = Task.Run(ListenLoop);
                _isActive = true;
                _context.Log(LogLevel.Info, ModuleName,
                    $"Local API server running on http://127.0.0.1:{ApiPort}/");
            }
            catch (Exception ex)
            {
                _context.Log(LogLevel.Warning, ModuleName,
                    $"Failed to start local API: {ex.Message}");
            }
        }

        public void Dispose()
        {
            _isActive = false;
            _cts?.Cancel();
            _listener?.Close();
        }

        public bool IsActive => _isActive;

        private async Task ListenLoop()
        {
            while (!_cts!.Token.IsCancellationRequested)
            {
                try
                {
                    var ctx = await _listener!.GetContextAsync();
                    _ = Task.Run(() => HandleRequest(ctx));
                }
                catch (ObjectDisposedException) { break; }
                catch (HttpListenerException) { break; }
                catch { }
            }
        }

        private void HandleRequest(HttpListenerContext ctx)
        {
            try
            {
                // CORS headers for browser extension
                ctx.Response.Headers.Add("Access-Control-Allow-Origin", "*");
                ctx.Response.Headers.Add("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
                ctx.Response.Headers.Add("Access-Control-Allow-Headers", "Content-Type");

                if (ctx.Request.HttpMethod == "OPTIONS")
                {
                    ctx.Response.StatusCode = 204;
                    ctx.Response.Close();
                    return;
                }

                var path = ctx.Request.Url?.AbsolutePath ?? "";
                object? result = null;

                switch (path)
                {
                    case "/api/check-url":
                        var url = GetQueryParam(ctx, "url") ?? ReadBodyString(ctx);
                        if (!string.IsNullOrEmpty(url) && _checkUrl != null)
                            result = _checkUrl(url);
                        else
                            result = new { error = "Missing 'url' parameter" };
                        break;

                    case "/api/check-urls":
                        var body = ReadBodyString(ctx);
                        if (!string.IsNullOrEmpty(body) && _checkUrls != null)
                        {
                            var urls = JsonSerializer.Deserialize<string[]>(body);
                            if (urls != null)
                                result = _checkUrls(urls);
                        }
                        else
                            result = new { error = "POST array of URLs" };
                        break;

                    case "/api/status":
                        result = new
                        {
                            service = "PCPlus Endpoint Protection",
                            version = "5.6.0",
                            active = true,
                            modules = new[] { "health", "security", "ransomware", "phishing", "dns-proxy" }
                        };
                        break;

                    case "/api/report-phishing":
                        var reportUrl = ReadBodyString(ctx);
                        if (!string.IsNullOrEmpty(reportUrl))
                        {
                            _context.Log(LogLevel.Info, ModuleName,
                                $"User reported phishing URL: {reportUrl}");
                            result = new { success = true, message = "Reported" };
                        }
                        break;

                    default:
                        result = new { error = "Unknown endpoint", available = new[] {
                            "/api/check-url", "/api/check-urls", "/api/status", "/api/report-phishing"
                        }};
                        break;
                }

                var json = JsonSerializer.Serialize(result ?? new { error = "No result" });
                var buffer = Encoding.UTF8.GetBytes(json);
                ctx.Response.ContentType = "application/json";
                ctx.Response.ContentLength64 = buffer.Length;
                ctx.Response.OutputStream.Write(buffer, 0, buffer.Length);
            }
            catch { }
            finally
            {
                try { ctx.Response.Close(); } catch { }
            }
        }

        private static string? GetQueryParam(HttpListenerContext ctx, string name)
        {
            return ctx.Request.QueryString[name];
        }

        private static string ReadBodyString(HttpListenerContext ctx)
        {
            try
            {
                if (!ctx.Request.HasEntityBody) return "";
                using var reader = new System.IO.StreamReader(ctx.Request.InputStream, ctx.Request.ContentEncoding);
                return reader.ReadToEnd();
            }
            catch { return ""; }
        }
    }
}
