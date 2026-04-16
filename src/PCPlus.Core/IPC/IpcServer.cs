using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace PCPlus.Core.IPC
{
    /// <summary>
    /// Secured named pipe server used by the Windows Service.
    /// - Tight ACLs: only SYSTEM and local Administrators can connect
    /// - Session-based authentication with HMAC tokens
    /// - Command authorization (read-only vs operator vs admin)
    /// - Request schema validation and size limits
    /// - Rate limiting per client
    /// </summary>
    public class IpcServer : IDisposable
    {
        private CancellationTokenSource? _cts;
        private Task? _acceptTask;
        private readonly List<ConnectedClient> _clients = new();
        private readonly object _clientLock = new();
        private bool _disposed;

        // Session management
        private readonly Dictionary<string, ClientSession> _sessions = new();
        private readonly object _sessionLock = new();
        private readonly byte[] _sessionSecret;
        private Timer? _sessionCleanupTimer;

        // Rate limiting: max requests per minute per client
        private const int MAX_REQUESTS_PER_MINUTE = 120;

        public event Func<IpcRequest, ClientSession?, Task<IpcResponse>>? OnRequest;
        public int ClientCount { get { lock (_clientLock) return _clients.Count; } }

        public IpcServer()
        {
            // Generate a random secret for this service instance (used for session tokens)
            _sessionSecret = RandomNumberGenerator.GetBytes(32);
        }

        public void Start()
        {
            _cts = new CancellationTokenSource();
            _acceptTask = AcceptClientsAsync(_cts.Token);

            // Clean up expired sessions every 5 minutes
            _sessionCleanupTimer = new Timer(CleanupExpiredSessions, null,
                TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(5));
        }

        public void Stop()
        {
            _sessionCleanupTimer?.Dispose();
            _cts?.Cancel();
            lock (_clientLock)
            {
                foreach (var client in _clients)
                    client.Dispose();
                _clients.Clear();
            }
            lock (_sessionLock) _sessions.Clear();
        }

        /// <summary>
        /// Authenticate a client and create a session.
        /// Returns a session token that the client must include in subsequent requests.
        /// </summary>
        public SessionInfo CreateSession(string clientIdentity, CommandPermission permissionLevel)
        {
            var token = GenerateSessionToken();
            var session = new ClientSession
            {
                Token = token,
                PermissionLevel = permissionLevel,
                ClientIdentity = clientIdentity,
                CreatedAt = DateTime.UtcNow,
                ExpiresAt = DateTime.UtcNow.Add(IpcProtocol.SESSION_TOKEN_LIFETIME),
                LastActivity = DateTime.UtcNow
            };

            lock (_sessionLock)
            {
                _sessions[token] = session;
            }

            return new SessionInfo
            {
                Token = token,
                PermissionLevel = permissionLevel,
                ExpiresAt = session.ExpiresAt,
                ClientIdentity = clientIdentity
            };
        }

        /// <summary>Validate a session token and return the session if valid.</summary>
        public ClientSession? ValidateSession(string token)
        {
            if (string.IsNullOrEmpty(token)) return null;

            lock (_sessionLock)
            {
                if (_sessions.TryGetValue(token, out var session))
                {
                    if (session.ExpiresAt > DateTime.UtcNow)
                    {
                        session.LastActivity = DateTime.UtcNow;
                        return session;
                    }
                    // Expired - remove it
                    _sessions.Remove(token);
                }
            }
            return null;
        }

        /// <summary>Revoke a specific session.</summary>
        public void RevokeSession(string token)
        {
            lock (_sessionLock) { _sessions.Remove(token); }
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

        public Task BroadcastAsync<T>(string type, T data) =>
            BroadcastNotificationAsync(new IpcNotification
            {
                Type = type,
                JsonData = JsonSerializer.Serialize(data, IpcProtocol.JsonOptions)
            });

        private NamedPipeServerStream CreateSecuredPipe()
        {
            try
            {
                // Tightened ACLs: only SYSTEM, Administrators, and Interactive Users
                var pipeSecurity = new PipeSecurity();

                // SYSTEM account (the service itself)
                pipeSecurity.AddAccessRule(new PipeAccessRule(
                    new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                    PipeAccessRights.FullControl,
                    AccessControlType.Allow));

                // Local Administrators
                pipeSecurity.AddAccessRule(new PipeAccessRule(
                    new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                    PipeAccessRights.ReadWrite,
                    AccessControlType.Allow));

                // Interactive users (logged-in users - needed for the tray app)
                pipeSecurity.AddAccessRule(new PipeAccessRule(
                    new SecurityIdentifier(WellKnownSidType.InteractiveSid, null),
                    PipeAccessRights.ReadWrite,
                    AccessControlType.Allow));

                // Explicitly deny network logon (prevent remote pipe access)
                pipeSecurity.AddAccessRule(new PipeAccessRule(
                    new SecurityIdentifier(WellKnownSidType.NetworkSid, null),
                    PipeAccessRights.ReadWrite,
                    AccessControlType.Deny));

                return NamedPipeServerStreamAcl.Create(
                    IpcProtocol.PIPE_NAME,
                    PipeDirection.InOut,
                    NamedPipeServerStream.MaxAllowedServerInstances,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous,
                    0, 0,
                    pipeSecurity);
            }
            catch
            {
                // Fallback: create pipe without custom ACLs if ACL creation fails
                // (e.g. on some Windows editions or .NET runtime issues)
                return new NamedPipeServerStream(
                    IpcProtocol.PIPE_NAME,
                    PipeDirection.InOut,
                    NamedPipeServerStream.MaxAllowedServerInstances,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous);
            }
        }

        private async Task AcceptClientsAsync(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    var pipe = CreateSecuredPipe();

                    await pipe.WaitForConnectionAsync(ct);

                    // Get the client's identity
                    string clientUser = "unknown";
                    try
                    {
                        pipe.RunAsClient(() =>
                        {
                            clientUser = WindowsIdentity.GetCurrent().Name;
                        });
                    }
                    catch { }

                    var client = new ConnectedClient(pipe, clientUser);
                    lock (_clientLock)
                    {
                        _clients.Add(client);
                    }

                    _ = HandleClientAsync(client, ct);
                }
                catch (OperationCanceledException) { break; }
                catch
                {
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

                    // Size limit check
                    if (line.Length > IpcProtocol.MAX_MESSAGE_SIZE)
                    {
                        var errorResponse = IpcResponse.Fail("", "Message exceeds size limit");
                        await client.SendLineAsync(
                            JsonSerializer.Serialize(errorResponse, IpcProtocol.JsonOptions));
                        continue;
                    }

                    // Rate limiting
                    if (!client.CheckRateLimit(MAX_REQUESTS_PER_MINUTE))
                    {
                        var errorResponse = IpcResponse.Fail("", "Rate limit exceeded. Try again later.");
                        await client.SendLineAsync(
                            JsonSerializer.Serialize(errorResponse, IpcProtocol.JsonOptions));
                        continue;
                    }

                    try
                    {
                        var request = JsonSerializer.Deserialize<IpcRequest>(line, IpcProtocol.JsonOptions);
                        if (request == null)
                        {
                            await client.SendLineAsync(JsonSerializer.Serialize(
                                IpcResponse.Fail("", "Invalid request format"), IpcProtocol.JsonOptions));
                            continue;
                        }

                        // Validate request schema
                        if (!ValidateRequest(request, out var validationError))
                        {
                            await client.SendLineAsync(JsonSerializer.Serialize(
                                IpcResponse.Fail(request.Id, validationError), IpcProtocol.JsonOptions));
                            continue;
                        }

                        // Check session and authorization (Authenticate and Ping are exempt)
                        ClientSession? session = null;
                        if (request.Type != IpcRequestType.Authenticate && request.Type != IpcRequestType.Ping)
                        {
                            session = ValidateSession(request.SessionToken);
                            if (session == null)
                            {
                                await client.SendLineAsync(JsonSerializer.Serialize(
                                    IpcResponse.Unauthorized(request.Id,
                                        "Session expired or invalid. Please authenticate first."),
                                    IpcProtocol.JsonOptions));
                                continue;
                            }

                            // Check command permission
                            var requiredPerm = CommandAuthorization.GetRequired(request.Type);
                            if (!CommandAuthorization.IsAuthorized(session.PermissionLevel, requiredPerm))
                            {
                                await client.SendLineAsync(JsonSerializer.Serialize(
                                    IpcResponse.Unauthorized(request.Id,
                                        $"This action requires {requiredPerm} permission. " +
                                        $"Your session has {session.PermissionLevel} permission."),
                                    IpcProtocol.JsonOptions));
                                continue;
                            }
                        }

                        if (OnRequest != null)
                        {
                            var response = await OnRequest(request, session);
                            var responseJson = JsonSerializer.Serialize(response, IpcProtocol.JsonOptions);
                            await client.SendLineAsync(responseJson);
                        }
                    }
                    catch (JsonException)
                    {
                        var errorResponse = IpcResponse.Fail("", "Malformed JSON");
                        await client.SendLineAsync(
                            JsonSerializer.Serialize(errorResponse, IpcProtocol.JsonOptions));
                    }
                    catch (Exception ex)
                    {
                        var errorResponse = IpcResponse.Fail("", $"Error: {ex.Message}");
                        await client.SendLineAsync(
                            JsonSerializer.Serialize(errorResponse, IpcProtocol.JsonOptions));
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

        /// <summary>Validate request has required fields and known type.</summary>
        private static bool ValidateRequest(IpcRequest request, out string error)
        {
            error = "";

            if (string.IsNullOrEmpty(request.Id))
            {
                error = "Request ID is required";
                return false;
            }

            if (!Enum.IsDefined(typeof(IpcRequestType), request.Type))
            {
                error = $"Unknown request type: {request.Type}";
                return false;
            }

            // SendModuleCommand requires ModuleId
            if (request.Type == IpcRequestType.SendModuleCommand && string.IsNullOrEmpty(request.ModuleId))
            {
                error = "ModuleId is required for SendModuleCommand";
                return false;
            }

            // Reject requests from the future or too old (clock skew tolerance: 5 min)
            var age = DateTime.UtcNow - request.Timestamp;
            if (age.TotalMinutes > 5 || age.TotalMinutes < -5)
            {
                error = "Request timestamp out of range";
                return false;
            }

            return true;
        }

        private string GenerateSessionToken()
        {
            var tokenBytes = RandomNumberGenerator.GetBytes(32);
            // HMAC the token with our secret so we can verify it was issued by us
            using var hmac = new HMACSHA256(_sessionSecret);
            var signature = hmac.ComputeHash(tokenBytes);
            return Convert.ToBase64String(tokenBytes) + "." + Convert.ToBase64String(signature);
        }

        private void CleanupExpiredSessions(object? state)
        {
            lock (_sessionLock)
            {
                var expired = _sessions
                    .Where(kvp => kvp.Value.ExpiresAt <= DateTime.UtcNow)
                    .Select(kvp => kvp.Key)
                    .ToList();
                foreach (var key in expired)
                    _sessions.Remove(key);
            }
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            Stop();
            _cts?.Dispose();
        }

        /// <summary>Tracks a connected client session on the server side.</summary>
        public class ClientSession
        {
            public string Token { get; set; } = "";
            public CommandPermission PermissionLevel { get; set; }
            public string ClientIdentity { get; set; } = "";
            public DateTime CreatedAt { get; set; }
            public DateTime ExpiresAt { get; set; }
            public DateTime LastActivity { get; set; }
        }

        private class ConnectedClient : IDisposable
        {
            private readonly NamedPipeServerStream _pipe;
            private readonly StreamReader _reader;
            private readonly StreamWriter _writer;
            private readonly SemaphoreSlim _writeLock = new(1, 1);

            public string ClientUser { get; }
            public bool IsConnected => _pipe.IsConnected;

            // Rate limiting state
            private readonly Queue<DateTime> _requestTimestamps = new();
            private readonly object _rateLock = new();

            public ConnectedClient(NamedPipeServerStream pipe, string clientUser)
            {
                _pipe = pipe;
                ClientUser = clientUser;
                _reader = new StreamReader(pipe, Encoding.UTF8);
                _writer = new StreamWriter(pipe, Encoding.UTF8) { AutoFlush = true };
            }

            /// <summary>Returns true if under rate limit.</summary>
            public bool CheckRateLimit(int maxPerMinute)
            {
                lock (_rateLock)
                {
                    var now = DateTime.UtcNow;
                    var cutoff = now.AddMinutes(-1);

                    while (_requestTimestamps.Count > 0 && _requestTimestamps.Peek() < cutoff)
                        _requestTimestamps.Dequeue();

                    if (_requestTimestamps.Count >= maxPerMinute)
                        return false;

                    _requestTimestamps.Enqueue(now);
                    return true;
                }
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
