using System.IO.Pipes;
using System.Text;
using System.Text.Json;

namespace PCPlus.Core.IPC
{
    /// <summary>
    /// Secured named pipe client used by the Tray App.
    /// - Authenticates with the service on connect
    /// - Includes session token in all requests
    /// - Auto-reconnects and re-authenticates
    /// - Thread-safe request/response with timeout
    /// </summary>
    public class IpcClient : IDisposable
    {
        private NamedPipeClientStream? _pipe;
        private StreamReader? _reader;
        private StreamWriter? _writer;
        private readonly SemaphoreSlim _sendLock = new(1, 1);
        private readonly SemaphoreSlim _connectLock = new(1, 1);
        private CancellationTokenSource? _listenerCts;
        private Task? _listenerTask;
        private bool _disposed;

        // Session state
        private string _sessionToken = "";
        private SessionInfo? _session;

        // Pending request tracking
        private readonly Dictionary<string, TaskCompletionSource<IpcResponse>> _pendingRequests = new();
        private readonly object _pendingLock = new();

        public event Action<IpcNotification>? OnNotification;
        public event Action<bool>? OnConnectionChanged;
        public bool IsConnected => _pipe?.IsConnected ?? false;
        public bool IsAuthenticated => _session != null && _session.ExpiresAt > DateTime.UtcNow;
        public CommandPermission PermissionLevel => _session?.PermissionLevel ?? CommandPermission.ReadOnly;

        public async Task ConnectAsync(int timeoutMs = 5000)
        {
            if (IsConnected) return;

            // Prevent concurrent connection attempts
            if (!await _connectLock.WaitAsync(0))
                return;

            try
            {
                if (IsConnected) return;

                // Dispose any stale pipe
                _listenerCts?.Cancel();
                _pipe?.Dispose();

                _pipe = new NamedPipeClientStream(".", IpcProtocol.PIPE_NAME,
                    PipeDirection.InOut, PipeOptions.Asynchronous);

                await _pipe.ConnectAsync(timeoutMs);
                _reader = new StreamReader(_pipe, Encoding.UTF8);
                _writer = new StreamWriter(_pipe, Encoding.UTF8) { AutoFlush = true };

                // Start listening for responses and notifications
                _listenerCts = new CancellationTokenSource();
                _listenerTask = ListenAsync(_listenerCts.Token);

                OnConnectionChanged?.Invoke(true);

                // Authenticate immediately after connecting
                await AuthenticateAsync();
            }
            finally
            {
                _connectLock.Release();
            }
        }

        /// <summary>Authenticate with the service to get a session token.</summary>
        public async Task<bool> AuthenticateAsync()
        {
            var request = new IpcRequest
            {
                Type = IpcRequestType.Authenticate,
                Parameters = new()
                {
                    ["clientType"] = "tray",
                    ["version"] = typeof(IpcClient).Assembly.GetName().Version?.ToString(3) ?? "4.3.0",
                    ["user"] = Environment.UserName,
                    ["machine"] = Environment.MachineName
                }
            };

            // Send without session token (auth is exempt)
            var response = await SendRawRequestAsync(request);
            if (response.Success)
            {
                _session = response.GetData<SessionInfo>();
                if (_session != null)
                {
                    _sessionToken = _session.Token;
                    return true;
                }
            }
            return false;
        }

        public async Task<IpcResponse> SendRequestAsync(IpcRequest request, int timeoutMs = 10000)
        {
            if (!IsConnected)
            {
                try { await ConnectAsync(); }
                catch { return IpcResponse.Fail(request.Id, "Service not available"); }
            }

            // Attach session token
            request.SessionToken = _sessionToken;
            return await SendRawRequestAsync(request, timeoutMs);
        }

        private async Task<IpcResponse> SendRawRequestAsync(IpcRequest request, int timeoutMs = 10000)
        {
            if (!IsConnected)
                return IpcResponse.Fail(request.Id, "Not connected");

            var tcs = new TaskCompletionSource<IpcResponse>();

            lock (_pendingLock)
            {
                _pendingRequests[request.Id] = tcs;
            }

            try
            {
                var json = JsonSerializer.Serialize(request, IpcProtocol.JsonOptions);

                await _sendLock.WaitAsync();
                try
                {
                    await _writer!.WriteLineAsync(json);
                }
                finally
                {
                    _sendLock.Release();
                }

                using var cts = new CancellationTokenSource(timeoutMs);
                cts.Token.Register(() => tcs.TrySetResult(
                    IpcResponse.Fail(request.Id, "Request timed out")));

                var response = await tcs.Task;

                // If we get an unauthorized response, try re-authenticating once
                if (!response.Success && response.Message.Contains("Session expired"))
                {
                    if (await AuthenticateAsync())
                    {
                        // Retry the original request with new token
                        request.SessionToken = _sessionToken;
                        return await SendRawRequestAsync(request, timeoutMs);
                    }
                }

                return response;
            }
            catch (Exception ex)
            {
                return IpcResponse.Fail(request.Id, $"IPC error: {ex.Message}");
            }
            finally
            {
                lock (_pendingLock)
                {
                    _pendingRequests.Remove(request.Id);
                }
            }
        }

        // Convenience methods for common requests
        public Task<IpcResponse> GetHealthSnapshotAsync() =>
            SendRequestAsync(new IpcRequest { Type = IpcRequestType.GetHealthSnapshot });

        public Task<IpcResponse> GetSecurityScoreAsync() =>
            SendRequestAsync(new IpcRequest { Type = IpcRequestType.GetSecurityScore });

        public Task<IpcResponse> RunSecurityScanAsync() =>
            SendRequestAsync(new IpcRequest { Type = IpcRequestType.RunSecurityScan }, 30000);

        public Task<IpcResponse> GetAllModuleStatusesAsync() =>
            SendRequestAsync(new IpcRequest { Type = IpcRequestType.GetAllModuleStatuses });

        public Task<IpcResponse> GetRecentAlertsAsync(int count = 20) =>
            SendRequestAsync(new IpcRequest
            {
                Type = IpcRequestType.GetRecentAlerts,
                Parameters = new() { ["count"] = count.ToString() }
            });

        public Task<IpcResponse> PingAsync() =>
            SendRequestAsync(new IpcRequest { Type = IpcRequestType.Ping }, 3000);

        public Task<IpcResponse> GetServiceStatusAsync() =>
            SendRequestAsync(new IpcRequest { Type = IpcRequestType.GetServiceStatus });

        public Task<IpcResponse> SendModuleCommandAsync(string moduleId, string action,
            Dictionary<string, string>? parameters = null) =>
            SendRequestAsync(new IpcRequest
            {
                Type = IpcRequestType.SendModuleCommand,
                ModuleId = moduleId,
                Action = action,
                Parameters = parameters ?? new()
            });

        private async Task ListenAsync(CancellationToken ct)
        {
            try
            {
                while (!ct.IsCancellationRequested && IsConnected)
                {
                    var line = await _reader!.ReadLineAsync(ct);
                    if (line == null) break;

                    ProcessMessage(line);
                }
            }
            catch (OperationCanceledException) { }
            catch { }
            finally
            {
                _session = null;
                _sessionToken = "";
                OnConnectionChanged?.Invoke(false);
            }
        }

        private void ProcessMessage(string json)
        {
            try
            {
                // Try as response first
                if (json.Contains("\"requestId\""))
                {
                    var response = JsonSerializer.Deserialize<IpcResponse>(json, IpcProtocol.JsonOptions);
                    if (response != null && !string.IsNullOrEmpty(response.RequestId))
                    {
                        TaskCompletionSource<IpcResponse>? tcs;
                        lock (_pendingLock)
                        {
                            _pendingRequests.TryGetValue(response.RequestId, out tcs);
                        }
                        tcs?.TrySetResult(response);
                        return;
                    }
                }

                // Try as notification
                if (json.Contains("\"type\""))
                {
                    var notification = JsonSerializer.Deserialize<IpcNotification>(json, IpcProtocol.JsonOptions);
                    if (notification != null)
                    {
                        // Handle session expiry notification
                        if (notification.Type == IpcNotification.SESSION_EXPIRED)
                        {
                            _session = null;
                            _sessionToken = "";
                            _ = AuthenticateAsync();
                        }

                        OnNotification?.Invoke(notification);
                    }
                }
            }
            catch { }
        }

        public void Disconnect()
        {
            _listenerCts?.Cancel();
            _writer?.Dispose();
            _reader?.Dispose();
            _pipe?.Dispose();
            _pipe = null;
            _session = null;
            _sessionToken = "";
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            Disconnect();
            _sendLock.Dispose();
            _listenerCts?.Dispose();
        }
    }
}
