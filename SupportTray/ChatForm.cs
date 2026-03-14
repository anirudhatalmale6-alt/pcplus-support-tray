using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Net.Http;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace SupportTray
{
    public class ChatForm : Form
    {
        private readonly AppConfig _config;
        private ClientWebSocket? _ws;
        private CancellationTokenSource? _cts;
        private RichTextBox _chatDisplay = null!;
        private TextBox _messageInput = null!;
        private Button _sendButton = null!;
        private Button _attachButton = null!;
        private Label _statusLabel = null!;
        private Panel _headerPanel = null!;
        private string _clientId;
        private bool _connected;

        public ChatForm(AppConfig config)
        {
            _config = config;
            _clientId = GetOrCreateClientId();
            InitializeUI();
        }

        private string GetOrCreateClientId()
        {
            var idFile = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "PCPlusSupport", "client_id.txt");
            try
            {
                if (File.Exists(idFile))
                    return File.ReadAllText(idFile).Trim();
            }
            catch { }

            var id = Guid.NewGuid().ToString();
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(idFile)!);
                File.WriteAllText(idFile, id);
            }
            catch { }
            return id;
        }

        private void InitializeUI()
        {
            Text = $"{_config.CompanyName} - Chat with Support";
            Size = new Size(480, 600);
            StartPosition = FormStartPosition.CenterScreen;
            MinimumSize = new Size(380, 450);
            BackColor = Color.FromArgb(15, 20, 30);
            Font = new Font("Segoe UI", 9.5f);

            // Header
            _headerPanel = new Panel
            {
                Dock = DockStyle.Top,
                Height = 56,
                BackColor = Color.FromArgb(0, 120, 212)
            };
            var headerLabel = new Label
            {
                Text = $"  {_config.CompanyName} Support",
                ForeColor = Color.White,
                Font = new Font("Segoe UI", 14, FontStyle.Bold),
                AutoSize = false,
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft,
                Padding = new Padding(8, 0, 0, 0)
            };
            _statusLabel = new Label
            {
                Text = "Connecting...",
                ForeColor = Color.FromArgb(180, 220, 255),
                Font = new Font("Segoe UI", 8.5f),
                AutoSize = false,
                Size = new Size(120, 20),
                Dock = DockStyle.Right,
                TextAlign = ContentAlignment.MiddleRight,
                Padding = new Padding(0, 0, 12, 0)
            };
            _headerPanel.Controls.Add(headerLabel);
            _headerPanel.Controls.Add(_statusLabel);
            Controls.Add(_headerPanel);

            // Chat display
            _chatDisplay = new RichTextBox
            {
                Dock = DockStyle.Fill,
                ReadOnly = true,
                BackColor = Color.FromArgb(20, 27, 40),
                ForeColor = Color.FromArgb(220, 230, 240),
                Font = new Font("Segoe UI", 10f),
                BorderStyle = BorderStyle.None,
                ScrollBars = RichTextBoxScrollBars.Vertical
            };
            Controls.Add(_chatDisplay);

            // Input area
            var inputPanel = new Panel
            {
                Dock = DockStyle.Bottom,
                Height = 60,
                BackColor = Color.FromArgb(25, 32, 48),
                Padding = new Padding(10, 10, 10, 10)
            };

            _attachButton = new Button
            {
                Text = "\U0001F4CE",
                Size = new Size(36, 38),
                Location = new Point(10, 11),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(35, 45, 65),
                ForeColor = Color.FromArgb(150, 170, 200),
                Font = new Font("Segoe UI", 12),
                Cursor = Cursors.Hand
            };
            _attachButton.FlatAppearance.BorderSize = 0;
            _attachButton.Click += AttachButton_Click;
            inputPanel.Controls.Add(_attachButton);

            _messageInput = new TextBox
            {
                Location = new Point(52, 11),
                Height = 38,
                BackColor = Color.FromArgb(35, 45, 65),
                ForeColor = Color.FromArgb(220, 230, 240),
                Font = new Font("Segoe UI", 10.5f),
                BorderStyle = BorderStyle.FixedSingle
            };
            _messageInput.KeyDown += (s, e) =>
            {
                if (e.KeyCode == Keys.Enter && !e.Shift)
                {
                    e.SuppressKeyPress = true;
                    SendMessage();
                }
            };
            inputPanel.Controls.Add(_messageInput);

            _sendButton = new Button
            {
                Text = "Send",
                Height = 38,
                Width = 70,
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(0, 120, 212),
                ForeColor = Color.White,
                Font = new Font("Segoe UI", 10, FontStyle.Bold),
                Cursor = Cursors.Hand
            };
            _sendButton.FlatAppearance.BorderSize = 0;
            _sendButton.Click += (s, e) => SendMessage();
            inputPanel.Controls.Add(_sendButton);

            Controls.Add(inputPanel);

            // Fix layout on resize
            Resize += (s, e) => LayoutInputPanel(inputPanel);
            Load += (s, e) => LayoutInputPanel(inputPanel);

            // Fix control order so chat area fills correctly
            Controls.SetChildIndex(inputPanel, 0);
            Controls.SetChildIndex(_chatDisplay, 1);
            Controls.SetChildIndex(_headerPanel, 2);

            // Connect on load
            Load += async (s, e) =>
            {
                LayoutInputPanel(inputPanel);
                await ConnectAsync();
            };

            FormClosing += (s, e) =>
            {
                _cts?.Cancel();
                try { _ws?.Dispose(); } catch { }
            };
        }

        private void LayoutInputPanel(Panel panel)
        {
            var pw = panel.ClientSize.Width;
            _attachButton.Location = new Point(8, 11);
            _sendButton.Location = new Point(pw - 78, 11);
            _messageInput.Location = new Point(50, 11);
            _messageInput.Width = pw - 136;
        }

        private async Task ConnectAsync()
        {
            var chatServerUrl = _config.RmmUrl.Replace("https://", "").Replace("http://", "");
            // The chat server runs on port 3456 on the same host
            var wsUrl = $"ws://{chatServerUrl}:3456/ws";

            // If a dedicated ChatServerUrl is configured, use that
            if (!string.IsNullOrEmpty(_config.TicketPortalUrl))
            {
                var host = _config.TicketPortalUrl.Replace("https://", "").Replace("http://", "").TrimEnd('/');
                wsUrl = $"ws://{host}/ws";
            }

            _cts = new CancellationTokenSource();

            while (!_cts.Token.IsCancellationRequested)
            {
                try
                {
                    _ws = new ClientWebSocket();
                    UpdateStatus("Connecting...", Color.FromArgb(245, 158, 11));

                    await _ws.ConnectAsync(new Uri(wsUrl), _cts.Token);
                    _connected = true;
                    UpdateStatus("Connected", Color.FromArgb(34, 197, 94));

                    // Authenticate
                    var authMsg = JsonSerializer.Serialize(new
                    {
                        type = "auth_client",
                        clientId = _clientId,
                        hostname = SystemInfo.GetHostname(),
                        username = SystemInfo.GetUsername(),
                        ip = SystemInfo.GetIPAddress(),
                        os = SystemInfo.GetOSVersion(),
                        agentId = SystemInfo.GetTacticalAgentId()
                    });
                    await SendWsAsync(authMsg);

                    // Receive loop
                    var buffer = new byte[8192];
                    while (_ws.State == WebSocketState.Open && !_cts.Token.IsCancellationRequested)
                    {
                        var result = await _ws.ReceiveAsync(new ArraySegment<byte>(buffer), _cts.Token);
                        if (result.MessageType == WebSocketMessageType.Close)
                            break;

                        var json = Encoding.UTF8.GetString(buffer, 0, result.Count);
                        HandleWsMessage(json);
                    }
                }
                catch (OperationCanceledException) { break; }
                catch
                {
                    _connected = false;
                    UpdateStatus("Disconnected", Color.FromArgb(239, 68, 68));
                }

                if (!_cts.Token.IsCancellationRequested)
                {
                    await Task.Delay(5000, _cts.Token).ConfigureAwait(false);
                }
            }
        }

        private void HandleWsMessage(string json)
        {
            try
            {
                var doc = JsonDocument.Parse(json);
                var type = doc.RootElement.GetProperty("type").GetString();

                switch (type)
                {
                    case "auth_ok":
                        AppendSystemMessage("Connected to support. Type your message below.");
                        break;

                    case "history":
                        if (doc.RootElement.TryGetProperty("messages", out var msgs))
                        {
                            foreach (var m in msgs.EnumerateArray())
                            {
                                var sender = m.GetProperty("sender").GetString();
                                var text = m.TryGetProperty("message", out var mp) ? mp.GetString() : "";
                                var attachment = m.TryGetProperty("attachment", out var ap) ? ap.GetString() : null;
                                var attachName = m.TryGetProperty("attachment_name", out var anp) ? anp.GetString() : null;

                                if (!string.IsNullOrEmpty(text))
                                    AppendChatMessage(sender == "client" ? "You" : "Support", text, sender == "support");
                                if (!string.IsNullOrEmpty(attachment))
                                    AppendChatMessage(sender == "client" ? "You" : "Support",
                                        $"[Attachment: {attachName ?? attachment}]", sender == "support");
                            }
                        }
                        break;

                    case "message":
                        {
                            var sender = doc.RootElement.GetProperty("sender").GetString();
                            var text = doc.RootElement.TryGetProperty("message", out var mp2) ? mp2.GetString() : "";
                            var attachment = doc.RootElement.TryGetProperty("attachment", out var ap2) ? ap2.GetString() : null;

                            if (sender == "support")
                            {
                                if (!string.IsNullOrEmpty(text))
                                    AppendChatMessage("Support", text, true);
                                if (!string.IsNullOrEmpty(attachment))
                                    AppendChatMessage("Support", "[File received]", true);

                                // Flash window if not focused
                                if (!Focused)
                                    FlashWindow();
                            }
                            else if (sender == "client")
                            {
                                // Echo of our own message
                                if (!string.IsNullOrEmpty(text))
                                    AppendChatMessage("You", text, false);
                                if (!string.IsNullOrEmpty(attachment))
                                    AppendChatMessage("You", "[File sent]", false);
                            }
                        }
                        break;
                }
            }
            catch { }
        }

        private void AppendChatMessage(string sender, string? text, bool isSupport)
        {
            if (string.IsNullOrEmpty(text)) return;

            if (InvokeRequired)
            {
                Invoke(() => AppendChatMessage(sender, text, isSupport));
                return;
            }

            var time = DateTime.Now.ToString("HH:mm");

            _chatDisplay.SelectionStart = _chatDisplay.TextLength;
            _chatDisplay.SelectionLength = 0;

            // Sender name
            _chatDisplay.SelectionColor = isSupport ? Color.FromArgb(0, 150, 255) : Color.FromArgb(34, 197, 94);
            _chatDisplay.SelectionFont = new Font("Segoe UI", 9, FontStyle.Bold);
            _chatDisplay.AppendText($"{sender}");

            // Time
            _chatDisplay.SelectionColor = Color.FromArgb(100, 120, 150);
            _chatDisplay.SelectionFont = new Font("Segoe UI", 7.5f);
            _chatDisplay.AppendText($"  {time}\n");

            // Message
            _chatDisplay.SelectionColor = Color.FromArgb(220, 230, 240);
            _chatDisplay.SelectionFont = new Font("Segoe UI", 10);
            _chatDisplay.AppendText($"  {text}\n\n");

            _chatDisplay.ScrollToCaret();
        }

        private void AppendSystemMessage(string text)
        {
            if (InvokeRequired)
            {
                Invoke(() => AppendSystemMessage(text));
                return;
            }

            _chatDisplay.SelectionColor = Color.FromArgb(100, 130, 170);
            _chatDisplay.SelectionFont = new Font("Segoe UI", 8.5f, FontStyle.Italic);
            _chatDisplay.AppendText($"  {text}\n\n");
            _chatDisplay.ScrollToCaret();
        }

        private void UpdateStatus(string text, Color color)
        {
            if (InvokeRequired)
            {
                Invoke(() => UpdateStatus(text, color));
                return;
            }
            _statusLabel.Text = text;
            _statusLabel.ForeColor = color;
        }

        private async void SendMessage()
        {
            var text = _messageInput.Text.Trim();
            if (string.IsNullOrEmpty(text) || !_connected) return;

            _messageInput.Text = "";

            var msg = JsonSerializer.Serialize(new { type = "message", text });
            await SendWsAsync(msg);
        }

        private async void AttachButton_Click(object? sender, EventArgs e)
        {
            using var ofd = new OpenFileDialog
            {
                Title = "Select file to send",
                Filter = "Images|*.jpg;*.jpeg;*.png;*.gif;*.bmp;*.webp|Documents|*.pdf;*.txt;*.log|All|*.*",
                Multiselect = false
            };

            if (ofd.ShowDialog() != DialogResult.OK) return;

            try
            {
                var chatServerUrl = _config.RmmUrl.Replace("https://", "").Replace("http://", "");
                var uploadUrl = $"http://{chatServerUrl}:3456/api/upload";

                using var http = new HttpClient();
                using var content = new MultipartFormDataContent();
                var fileBytes = File.ReadAllBytes(ofd.FileName);
                content.Add(new ByteArrayContent(fileBytes), "file", Path.GetFileName(ofd.FileName));

                var response = await http.PostAsync(uploadUrl, content);
                var responseJson = await response.Content.ReadAsStringAsync();
                var doc = JsonDocument.Parse(responseJson);
                var filename = doc.RootElement.GetProperty("filename").GetString();
                var originalName = doc.RootElement.GetProperty("originalName").GetString();

                var msg = JsonSerializer.Serialize(new
                {
                    type = "message",
                    text = "",
                    attachment = filename,
                    attachmentName = originalName
                });
                await SendWsAsync(msg);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to upload file: {ex.Message}", "Upload Error",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private async Task SendWsAsync(string message)
        {
            if (_ws?.State != WebSocketState.Open) return;
            var bytes = Encoding.UTF8.GetBytes(message);
            try
            {
                await _ws.SendAsync(new ArraySegment<byte>(bytes), WebSocketMessageType.Text, true,
                    _cts?.Token ?? CancellationToken.None);
            }
            catch { }
        }

        private void FlashWindow()
        {
            // Simple flash by changing title
            var originalTitle = Text;
            Text = "*** New Message ***";
            var timer = new System.Windows.Forms.Timer { Interval = 1000 };
            var count = 0;
            timer.Tick += (s, e) =>
            {
                count++;
                Text = count % 2 == 0 ? "*** New Message ***" : originalTitle;
                if (count >= 6 || Focused)
                {
                    Text = originalTitle;
                    timer.Stop();
                    timer.Dispose();
                }
            };
            timer.Start();
        }
    }
}
