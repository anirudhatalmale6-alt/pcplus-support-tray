using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace PCPlus.Core.IPC
{
    /// <summary>
    /// Named pipe server used by the Windows Service.
    /// Accepts connections from tray apps, handles requests, pushes notifications.
    /// Supports multiple simultaneous tray connections.
    /// </summary>
    public class IpcServer : IDisposable
    {
        private CancellationTokenSource? _cts;
        private Task? _acceptTask;
        private readonly List<ConnectedClient> _clients = new();
        private readonly object _clientLock = new();
        private bool _disposed;

        public event Func<IpcRequest, Task<IpcResponse>>? OnRequest;
        public int ClientCount { get { lock (_clientLock) return _clients.Count; } }

        public void Start()
        {
            _cts = new CancellationTokenSource();
            _acceptTask = AcceptClientsAsync(_cts.Token);
        }

        public void Stop()
        {
            _cts?.Cancel();
            lock (_clientLock)
            {
                foreach (var client in _clients)
                    client.Dispose();
                _clients.Clear();
            }
        }

        /// <summary>Push a notification to all connected tray apps.</summary>
        public async Task BroadcastNotificationAsync(IpcNotification notification)
        {
            var json = JsonSerializer.Serialize(notification, IpcProtocol.JsonOptions);
            List<ConnectedClient> snapshot;

            lock (_clientLock)
            {
                snapshot = new List<ConnectedClient>(_clients);
            }

            var disconnected = new List<ConnectedClient>();
            foreach (var client in snapshot)
            {
                try
                {
                    await client.SendLineAsync(json);
                }
                catch
                {
                    disconnected.Add(client);
                }
            }

            // Clean up disconnected clients
            if (disconnected.Count > 0)
            {
                lock (_clientLock)
                {
                    foreach (var dc in disconnected)
                    {
                        _clients.Remove(dc);
                        dc.Dispose();
                    }
                }
            }
        }

        /// <summary>Push a notification to all tray apps (typed helper).</summary>
        public Task BroadcastAsync<T>(string type, T data) =>
            BroadcastNotificationAsync(new IpcNotification
            {
                Type = type,
                JsonData = JsonSerializer.Serialize(data, IpcProtocol.JsonOptions)
            });

        private async Task AcceptClientsAsync(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    // Create pipe with security that allows any local user to connect
                    var pipeSecurity = new PipeSecurity();
                    pipeSecurity.AddAccessRule(new PipeAccessRule(
                        new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null),
                        PipeAccessRights.ReadWrite,
                        AccessControlType.Allow));

                    var pipe = NamedPipeServerStreamAcl.Create(
                        IpcProtocol.PIPE_NAME,
                        PipeDirection.InOut,
                        NamedPipeServerStream.MaxAllowedServerInstances,
                        PipeTransmissionMode.Byte,
                        PipeOptions.Asynchronous,
                        0, 0,
                        pipeSecurity);

                    await pipe.WaitForConnectionAsync(ct);

                    var client = new ConnectedClient(pipe);
                    lock (_clientLock)
                    {
                        _clients.Add(client);
                    }

                    // Handle this client in background
                    _ = HandleClientAsync(client, ct);
                }
                catch (OperationCanceledException) { break; }
                catch
                {
                    // Wait a bit before retrying
                    try { await Task.Delay(1000, ct); } catch { break; }
                }
            }
        }

        private async Task HandleClientAsync(ConnectedClient client, CancellationToken ct)
        {
            try
            {
                while (!ct.IsCancellationRequested && client.IsConnected)
                {
                    var line = await client.ReadLineAsync(ct);
                    if (line == null) break;

                    try
                    {
                        var request = JsonSerializer.Deserialize<IpcRequest>(line, IpcProtocol.JsonOptions);
                        if (request != null && OnRequest != null)
                        {
                            var response = await OnRequest(request);
                            var responseJson = JsonSerializer.Serialize(response, IpcProtocol.JsonOptions);
                            await client.SendLineAsync(responseJson);
                        }
                    }
                    catch (Exception ex)
                    {
                        var errorResponse = IpcResponse.Fail("", $"Error: {ex.Message}");
                        var errorJson = JsonSerializer.Serialize(errorResponse, IpcProtocol.JsonOptions);
                        await client.SendLineAsync(errorJson);
                    }
                }
            }
            catch { }
            finally
            {
                lock (_clientLock)
                {
                    _clients.Remove(client);
                }
                client.Dispose();
            }
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            Stop();
            _cts?.Dispose();
        }

        private class ConnectedClient : IDisposable
        {
            private readonly NamedPipeServerStream _pipe;
            private readonly StreamReader _reader;
            private readonly StreamWriter _writer;
            private readonly SemaphoreSlim _writeLock = new(1, 1);

            public bool IsConnected => _pipe.IsConnected;

            public ConnectedClient(NamedPipeServerStream pipe)
            {
                _pipe = pipe;
                _reader = new StreamReader(pipe, Encoding.UTF8);
                _writer = new StreamWriter(pipe, Encoding.UTF8) { AutoFlush = true };
            }

            public async Task<string?> ReadLineAsync(CancellationToken ct)
            {
                return await _reader.ReadLineAsync(ct);
            }

            public async Task SendLineAsync(string line)
            {
                await _writeLock.WaitAsync();
                try
                {
                    await _writer.WriteLineAsync(line);
                }
                finally
                {
                    _writeLock.Release();
                }
            }

            public void Dispose()
            {
                _writer.Dispose();
                _reader.Dispose();
                _pipe.Dispose();
                _writeLock.Dispose();
            }
        }
    }
}
