using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Net.Http;
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
        private RichTextBox _chatDisplay = null!;
        private TextBox _messageInput = null!;
        private Button _sendButton = null!;
        private Button _attachButton = null!;
        private Label _statusLabel = null!;
        private Panel _headerPanel = null!;
        private ComboBox _ticketSelector = null!;
        private Button _newTicketButton = null!;
        private ZammadApi? _zammadApi;
        private int? _currentTicketId;
        private string? _currentTicketNumber;
        private System.Windows.Forms.Timer? _refreshTimer;
        private int _lastArticleId;
        private bool _loading;

        public ChatForm(AppConfig config)
        {
            _config = config;
            InitializeZammad();
            InitializeUI();
        }

        private void InitializeZammad()
        {
            if (!string.IsNullOrEmpty(_config.ZammadUrl) && !string.IsNullOrEmpty(_config.ZammadApiToken))
            {
                _zammadApi = new ZammadApi(_config.ZammadUrl, _config.ZammadApiToken);
            }
        }

        private void InitializeUI()
        {
            Text = $"{_config.CompanyName} - Support Chat";
            Size = new Size(520, 650);
            StartPosition = FormStartPosition.CenterScreen;
            MinimumSize = new Size(400, 500);
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
                Text = "Ready",
                ForeColor = Color.FromArgb(180, 220, 255),
                Font = new Font("Segoe UI", 8.5f),
                AutoSize = false,
                Size = new Size(140, 20),
                Dock = DockStyle.Right,
                TextAlign = ContentAlignment.MiddleRight,
                Padding = new Padding(0, 0, 12, 0)
            };
            _headerPanel.Controls.Add(headerLabel);
            _headerPanel.Controls.Add(_statusLabel);
            Controls.Add(_headerPanel);

            // Ticket selector bar
            var ticketBar = new Panel
            {
                Dock = DockStyle.Top,
                Height = 40,
                BackColor = Color.FromArgb(20, 28, 45),
                Padding = new Padding(8, 6, 8, 6)
            };

            _ticketSelector = new ComboBox
            {
                Location = new Point(8, 8),
                Width = 340,
                DropDownStyle = ComboBoxStyle.DropDownList,
                BackColor = Color.FromArgb(35, 45, 65),
                ForeColor = Color.FromArgb(220, 230, 240),
                Font = new Font("Segoe UI", 9f),
                FlatStyle = FlatStyle.Flat
            };
            _ticketSelector.SelectedIndexChanged += async (s, e) => await OnTicketSelected();
            ticketBar.Controls.Add(_ticketSelector);

            _newTicketButton = new Button
            {
                Text = "+ New",
                Size = new Size(65, 26),
                Location = new Point(355, 7),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(0, 120, 212),
                ForeColor = Color.White,
                Font = new Font("Segoe UI", 8.5f, FontStyle.Bold),
                Cursor = Cursors.Hand
            };
            _newTicketButton.FlatAppearance.BorderSize = 0;
            _newTicketButton.Click += (s, e) => StartNewConversation();
            ticketBar.Controls.Add(_newTicketButton);

            Controls.Add(ticketBar);

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
            _attachButton.Click += async (s, e) => await AttachAndSend();
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
            _messageInput.KeyDown += async (s, e) =>
            {
                if (e.KeyCode == Keys.Enter && !e.Shift)
                {
                    e.SuppressKeyPress = true;
                    await SendMessage();
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
            _sendButton.Click += async (s, e) => await SendMessage();
            inputPanel.Controls.Add(_sendButton);

            Controls.Add(inputPanel);

            // Fix layout on resize
            Resize += (s, e) =>
            {
                LayoutInputPanel(inputPanel);
                LayoutTicketBar(ticketBar);
            };
            Load += async (s, e) =>
            {
                LayoutInputPanel(inputPanel);
                LayoutTicketBar(ticketBar);
                await LoadTickets();
            };

            // Fix control order so chat area fills correctly
            Controls.SetChildIndex(inputPanel, 0);
            Controls.SetChildIndex(_chatDisplay, 1);
            Controls.SetChildIndex(ticketBar, 2);
            Controls.SetChildIndex(_headerPanel, 3);

            FormClosing += (s, e) =>
            {
                _refreshTimer?.Stop();
                _refreshTimer?.Dispose();
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

        private void LayoutTicketBar(Panel panel)
        {
            var pw = panel.ClientSize.Width;
            _newTicketButton.Location = new Point(pw - 78, 7);
            _ticketSelector.Width = pw - 95;
        }

        private async Task LoadTickets()
        {
            if (_zammadApi == null)
            {
                AppendSystemMessage("Zammad is not configured. Please contact your administrator.");
                return;
            }

            UpdateStatus("Loading tickets...", Color.FromArgb(245, 158, 11));

            var tickets = await _zammadApi.GetMyTicketsAsync();

            _ticketSelector.Items.Clear();
            _ticketSelector.Items.Add("-- Select a conversation --");

            foreach (var t in tickets)
            {
                _ticketSelector.Items.Add(new TicketItem(t));
            }

            _ticketSelector.SelectedIndex = 0;
            UpdateStatus("Ready", Color.FromArgb(34, 197, 94));

            if (tickets.Count == 0)
            {
                AppendSystemMessage("Welcome! Click '+ New' or just type a message to start a support conversation.");
            }
            else
            {
                AppendSystemMessage($"You have {tickets.Count} open ticket(s). Select one to continue, or click '+ New' for a new conversation.");
            }
        }

        private async Task OnTicketSelected()
        {
            if (_ticketSelector.SelectedItem is TicketItem item)
            {
                _currentTicketId = item.Ticket.Id;
                _currentTicketNumber = item.Ticket.Number;
                _lastArticleId = 0;
                _chatDisplay.Clear();
                await LoadConversation();
                StartRefreshTimer();
            }
            else
            {
                _currentTicketId = null;
                _currentTicketNumber = null;
                StopRefreshTimer();
            }
        }

        private async Task LoadConversation()
        {
            if (_zammadApi == null || !_currentTicketId.HasValue) return;
            _loading = true;

            UpdateStatus("Loading...", Color.FromArgb(245, 158, 11));

            var articles = await _zammadApi.GetTicketArticlesAsync(_currentTicketId.Value);

            _chatDisplay.Clear();
            foreach (var a in articles)
            {
                var isSupport = a.Sender.Contains("Agent", StringComparison.OrdinalIgnoreCase) ||
                                a.From.Contains("pcpluscomputing", StringComparison.OrdinalIgnoreCase);
                var senderName = isSupport ? "Support" : "You";
                var time = TryParseTime(a.CreatedAt);

                if (!string.IsNullOrWhiteSpace(a.Body))
                    AppendChatMessage(senderName, a.Body, isSupport, time);

                _lastArticleId = Math.Max(_lastArticleId, a.Id);
            }

            UpdateStatus($"Ticket #{_currentTicketNumber}", Color.FromArgb(34, 197, 94));
            _loading = false;
        }

        private void StartRefreshTimer()
        {
            StopRefreshTimer();
            _refreshTimer = new System.Windows.Forms.Timer { Interval = 15000 }; // 15 seconds
            _refreshTimer.Tick += async (s, e) => await CheckForNewMessages();
            _refreshTimer.Start();
        }

        private void StopRefreshTimer()
        {
            _refreshTimer?.Stop();
            _refreshTimer?.Dispose();
            _refreshTimer = null;
        }

        private async Task CheckForNewMessages()
        {
            if (_zammadApi == null || !_currentTicketId.HasValue || _loading) return;

            try
            {
                var articles = await _zammadApi.GetTicketArticlesAsync(_currentTicketId.Value);
                foreach (var a in articles)
                {
                    if (a.Id > _lastArticleId)
                    {
                        var isSupport = a.Sender.Contains("Agent", StringComparison.OrdinalIgnoreCase) ||
                                        a.From.Contains("pcpluscomputing", StringComparison.OrdinalIgnoreCase);
                        var senderName = isSupport ? "Support" : "You";
                        var time = TryParseTime(a.CreatedAt);

                        if (!string.IsNullOrWhiteSpace(a.Body))
                            AppendChatMessage(senderName, a.Body, isSupport, time);

                        _lastArticleId = Math.Max(_lastArticleId, a.Id);

                        if (isSupport && !Focused)
                            FlashWindow();
                    }
                }
            }
            catch { }
        }

        private void StartNewConversation()
        {
            _currentTicketId = null;
            _currentTicketNumber = null;
            _lastArticleId = 0;
            _chatDisplay.Clear();
            StopRefreshTimer();
            _ticketSelector.SelectedIndex = 0;
            AppendSystemMessage("Type your message below to start a new support conversation.");
            _messageInput.Focus();
        }

        private async Task SendMessage()
        {
            var text = _messageInput.Text.Trim();
            if (string.IsNullOrEmpty(text) || _zammadApi == null) return;

            _messageInput.Text = "";
            _sendButton.Enabled = false;

            try
            {
                if (!_currentTicketId.HasValue)
                {
                    // Create new ticket
                    UpdateStatus("Creating ticket...", Color.FromArgb(245, 158, 11));

                    var hostname = SystemInfo.GetHostname();
                    var subject = text.Length > 60 ? text.Substring(0, 60) + "..." : text;
                    var body = text + "\n\n--- System Info ---\n" +
                              $"Computer: {hostname}\n" +
                              $"User: {SystemInfo.GetUsername()}\n" +
                              $"OS: {SystemInfo.GetOSVersion()}\n" +
                              $"IP: {SystemInfo.GetIPAddress()}\n" +
                              $"Agent ID: {SystemInfo.GetTacticalAgentId() ?? "N/A"}";

                    var email = _config.SupportEmail;
                    if (string.IsNullOrEmpty(email)) email = "customer@pcpluscomputing.com";

                    var result = await _zammadApi.CreateTicketAsync(
                        $"[{hostname}] {subject}", body, email);

                    if (result.Success && result.TicketId.HasValue)
                    {
                        _currentTicketId = result.TicketId;
                        // Extract ticket number from message
                        var match = System.Text.RegularExpressions.Regex.Match(
                            result.Message, @"#(\S+)");
                        _currentTicketNumber = match.Success ? match.Groups[1].Value : result.TicketId.ToString();

                        AppendChatMessage("You", text, false);
                        UpdateStatus($"Ticket #{_currentTicketNumber}", Color.FromArgb(34, 197, 94));

                        // Refresh ticket list
                        await LoadTickets();
                        // Select the new ticket
                        for (int i = 0; i < _ticketSelector.Items.Count; i++)
                        {
                            if (_ticketSelector.Items[i] is TicketItem ti && ti.Ticket.Id == _currentTicketId)
                            {
                                _ticketSelector.SelectedIndex = i;
                                break;
                            }
                        }

                        StartRefreshTimer();
                    }
                    else
                    {
                        AppendSystemMessage($"Failed to create ticket: {result.Message}");
                        UpdateStatus("Error", Color.FromArgb(239, 68, 68));
                    }
                }
                else
                {
                    // Add message to existing ticket
                    var result = await _zammadApi.AddMessageAsync(_currentTicketId.Value, text);
                    if (result.Success)
                    {
                        AppendChatMessage("You", text, false);
                        if (result.ArticleId.HasValue)
                            _lastArticleId = Math.Max(_lastArticleId, result.ArticleId.Value);
                    }
                    else
                    {
                        AppendSystemMessage($"Failed to send: {result.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                AppendSystemMessage($"Error: {ex.Message}");
            }

            _sendButton.Enabled = true;
            _messageInput.Focus();
        }

        private async Task AttachAndSend()
        {
            using var ofd = new OpenFileDialog
            {
                Title = "Select file to send",
                Filter = "Images|*.jpg;*.jpeg;*.png;*.gif;*.bmp;*.webp|Documents|*.pdf;*.txt;*.log|All|*.*",
                Multiselect = false
            };

            if (ofd.ShowDialog() != DialogResult.OK || _zammadApi == null) return;

            try
            {
                if (!_currentTicketId.HasValue)
                {
                    // Create ticket first with the filename as subject
                    var hostname = SystemInfo.GetHostname();
                    var fileName = Path.GetFileName(ofd.FileName);
                    var body = $"File attachment: {fileName}\n\n--- System Info ---\n" +
                              $"Computer: {hostname}\nUser: {SystemInfo.GetUsername()}\n" +
                              $"OS: {SystemInfo.GetOSVersion()}\nIP: {SystemInfo.GetIPAddress()}";

                    var result = await _zammadApi.CreateTicketAsync(
                        $"[{hostname}] File: {fileName}", body, _config.SupportEmail, ofd.FileName);

                    if (result.Success && result.TicketId.HasValue)
                    {
                        _currentTicketId = result.TicketId;
                        AppendChatMessage("You", $"[File sent: {fileName}]", false);
                        UpdateStatus($"Ticket #{result.TicketId}", Color.FromArgb(34, 197, 94));
                        StartRefreshTimer();
                    }
                    else
                    {
                        AppendSystemMessage($"Failed: {result.Message}");
                    }
                }
                else
                {
                    // Add attachment to existing ticket
                    var result = await _zammadApi.AddMessageAsync(
                        _currentTicketId.Value,
                        $"File attached: {Path.GetFileName(ofd.FileName)}",
                        ofd.FileName);

                    if (result.Success)
                    {
                        AppendChatMessage("You", $"[File sent: {Path.GetFileName(ofd.FileName)}]", false);
                        if (result.ArticleId.HasValue)
                            _lastArticleId = Math.Max(_lastArticleId, result.ArticleId.Value);
                    }
                    else
                    {
                        AppendSystemMessage($"Upload failed: {result.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to upload file: {ex.Message}", "Upload Error",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void AppendChatMessage(string sender, string? text, bool isSupport, string? time = null)
        {
            if (string.IsNullOrEmpty(text)) return;

            if (InvokeRequired)
            {
                Invoke(() => AppendChatMessage(sender, text, isSupport, time));
                return;
            }

            var displayTime = time ?? DateTime.Now.ToString("HH:mm");

            _chatDisplay.SelectionStart = _chatDisplay.TextLength;
            _chatDisplay.SelectionLength = 0;

            // Sender name
            _chatDisplay.SelectionColor = isSupport ? Color.FromArgb(0, 150, 255) : Color.FromArgb(34, 197, 94);
            _chatDisplay.SelectionFont = new Font("Segoe UI", 9, FontStyle.Bold);
            _chatDisplay.AppendText($"{sender}");

            // Time
            _chatDisplay.SelectionColor = Color.FromArgb(100, 120, 150);
            _chatDisplay.SelectionFont = new Font("Segoe UI", 7.5f);
            _chatDisplay.AppendText($"  {displayTime}\n");

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

        private static string TryParseTime(string isoTime)
        {
            try
            {
                if (DateTime.TryParse(isoTime, out var dt))
                    return dt.ToLocalTime().ToString("MMM dd HH:mm");
            }
            catch { }
            return "";
        }

        private void FlashWindow()
        {
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

        private class TicketItem
        {
            public TicketSummary Ticket { get; }
            public TicketItem(TicketSummary ticket) { Ticket = ticket; }
            public override string ToString()
            {
                var state = Ticket.State.ToUpper();
                return $"#{Ticket.Number} [{state}] {Ticket.Title}";
            }
        }
    }
}
