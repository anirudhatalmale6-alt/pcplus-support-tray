using System.IO.Pipes;
using System.Text;
using System.Text.Json;

namespace PCPlus.Core.IPC
{
    /// <summary>
    /// Named pipe client used by the Tray App to communicate with the Windows Service.
    /// Thread-safe, auto-reconnects, supports request/response and notification subscription.
    /// </summary>
    public class IpcClient : IDisposable
    {
        private NamedPipeClientStream? _pipe;
        private StreamReader? _reader;
        private StreamWriter? _writer;
        private readonly SemaphoreSlim _sendLock = new(1, 1);
        private CancellationTokenSource? _listenerCts;
        private Task? _listenerTask;
        private bool _disposed;

        // Pending request tracking
        private readonly Dictionary<string, TaskCompletionSource<IpcResponse>> _pendingRequests = new();
        private readonly object _pendingLock = new();

        public event Action<IpcNotification>? OnNotification;
        public event Action<bool>? OnConnectionChanged;
        public bool IsConnected => _pipe?.IsConnected ?? false;

        public async Task ConnectAsync(int timeoutMs = 5000)
        {
            if (IsConnected) return;

            _pipe = new NamedPipeClientStream(".", IpcProtocol.PIPE_NAME,
                PipeDirection.InOut, PipeOptions.Asynchronous);

            await _pipe.ConnectAsync(timeoutMs);
            _reader = new StreamReader(_pipe, Encoding.UTF8);
            _writer = new StreamWriter(_pipe, Encoding.UTF8) { AutoFlush = true };

            // Start listening for responses and notifications
            _listenerCts = new CancellationTokenSource();
            _listenerTask = ListenAsync(_listenerCts.Token);

            OnConnectionChanged?.Invoke(true);
        }

        public async Task<IpcResponse> SendRequestAsync(IpcRequest request, int timeoutMs = 10000)
        {
            if (!IsConnected)
            {
                try { await ConnectAsync(); }
                catch { return IpcResponse.Fail(request.Id, "Service not available"); }
            }

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

                return await tcs.Task;
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
                    if (line == null) break; // Pipe closed

                    ProcessMessage(line);
                }
            }
            catch (OperationCanceledException) { }
            catch { }
            finally
            {
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
