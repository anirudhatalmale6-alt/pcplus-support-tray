using System;
using System.Drawing;
using System.IO;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace SupportTray
{
    public class TicketForm : Form
    {
        private readonly AppConfig _config;
        private TextBox _subjectBox = null!;
        private RichTextBox _descriptionBox = null!;
        private CheckBox _includeSystemInfo = null!;
        private CheckBox _includeScreenshot = null!;
        private Button _submitButton = null!;
        private Button _cancelButton = null!;
        private Label _statusLabel = null!;
        private PictureBox _screenshotPreview = null!;
        private string? _screenshotPath;

        public TicketForm(AppConfig config)
        {
            _config = config;
            InitializeUI();
        }

        private void InitializeUI()
        {
            Text = $"{_config.CompanyName} - Create Support Ticket";
            Size = new Size(550, 580);
            StartPosition = FormStartPosition.CenterScreen;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = false;
            BackColor = Color.White;
            Font = new Font("Segoe UI", 9.5f);

            // Header
            var header = new Panel
            {
                Dock = DockStyle.Top,
                Height = 60,
                BackColor = Color.FromArgb(0, 120, 212)
            };
            var headerLabel = new Label
            {
                Text = "  Create Support Ticket",
                ForeColor = Color.White,
                Font = new Font("Segoe UI", 16, FontStyle.Bold),
                AutoSize = false,
                Size = new Size(500, 40),
                Location = new Point(10, 12),
                TextAlign = ContentAlignment.MiddleLeft
            };
            header.Controls.Add(headerLabel);
            Controls.Add(header);

            int y = 75;

            // Subject
            Controls.Add(new Label { Text = "Subject:", Location = new Point(20, y), AutoSize = true, Font = new Font("Segoe UI", 9.5f, FontStyle.Bold) });
            y += 22;
            _subjectBox = new TextBox
            {
                Location = new Point(20, y),
                Size = new Size(495, 28),
                PlaceholderText = "Brief description of your issue..."
            };
            Controls.Add(_subjectBox);
            y += 38;

            // Description
            Controls.Add(new Label { Text = "Description:", Location = new Point(20, y), AutoSize = true, Font = new Font("Segoe UI", 9.5f, FontStyle.Bold) });
            y += 22;
            _descriptionBox = new RichTextBox
            {
                Location = new Point(20, y),
                Size = new Size(495, 150),
                BorderStyle = BorderStyle.FixedSingle
            };
            Controls.Add(_descriptionBox);
            y += 160;

            // Include system info checkbox
            _includeSystemInfo = new CheckBox
            {
                Text = "Include system information (hostname, IP, OS, hardware)",
                Location = new Point(20, y),
                AutoSize = true,
                Checked = true
            };
            Controls.Add(_includeSystemInfo);
            y += 28;

            // Include screenshot checkbox
            _includeScreenshot = new CheckBox
            {
                Text = "Attach screenshot of current screen",
                Location = new Point(20, y),
                AutoSize = true,
                Checked = false
            };
            _includeScreenshot.CheckedChanged += (s, e) =>
            {
                if (_includeScreenshot.Checked)
                {
                    _screenshotPath = ScreenCapture.CaptureFullScreen();
                    if (_screenshotPreview != null && File.Exists(_screenshotPath))
                    {
                        using var img = Image.FromFile(_screenshotPath);
                        _screenshotPreview.Image = new Bitmap(img, new Size(200, 120));
                        _screenshotPreview.Visible = true;
                    }
                }
                else
                {
                    if (_screenshotPreview != null)
                    {
                        _screenshotPreview.Image?.Dispose();
                        _screenshotPreview.Image = null;
                        _screenshotPreview.Visible = false;
                    }
                    _screenshotPath = null;
                }
            };
            Controls.Add(_includeScreenshot);
            y += 28;

            // Screenshot preview
            _screenshotPreview = new PictureBox
            {
                Location = new Point(20, y),
                Size = new Size(200, 120),
                SizeMode = PictureBoxSizeMode.Zoom,
                BorderStyle = BorderStyle.FixedSingle,
                Visible = false
            };
            Controls.Add(_screenshotPreview);
            y += 130;

            // Status label
            _statusLabel = new Label
            {
                Text = "",
                Location = new Point(20, y),
                Size = new Size(300, 25),
                ForeColor = Color.Gray
            };
            Controls.Add(_statusLabel);

            // Buttons
            _submitButton = new Button
            {
                Text = "Submit Ticket",
                Location = new Point(305, y - 5),
                Size = new Size(100, 35),
                BackColor = Color.FromArgb(0, 120, 212),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Cursor = Cursors.Hand
            };
            _submitButton.FlatAppearance.BorderSize = 0;
            _submitButton.Click += async (s, e) => await SubmitTicket();
            Controls.Add(_submitButton);

            _cancelButton = new Button
            {
                Text = "Cancel",
                Location = new Point(415, y - 5),
                Size = new Size(100, 35),
                FlatStyle = FlatStyle.Flat,
                Cursor = Cursors.Hand
            };
            _cancelButton.Click += (s, e) => Close();
            Controls.Add(_cancelButton);
        }

        private async Task SubmitTicket()
        {
            if (string.IsNullOrWhiteSpace(_subjectBox.Text))
            {
                MessageBox.Show("Please enter a subject.", "Required", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                _subjectBox.Focus();
                return;
            }

            _submitButton.Enabled = false;
            _statusLabel.Text = "Submitting ticket...";
            _statusLabel.ForeColor = Color.FromArgb(0, 120, 212);

            var description = _descriptionBox.Text;

            if (_includeSystemInfo.Checked)
            {
                description += "\n\n--- System Information ---\n" + SystemInfo.GetFullReport();
            }

            if (_includeScreenshot.Checked && !string.IsNullOrEmpty(_screenshotPath))
            {
                description += $"\n\n[Screenshot attached: {Path.GetFileName(_screenshotPath)}]";
            }

            if (!string.IsNullOrEmpty(_config.RmmApiKey))
            {
                var api = new TacticalRmmApi(_config.RmmUrl, _config.RmmApiKey);
                var agentId = SystemInfo.GetTacticalAgentId();
                var result = await api.CreateTicketAsync(_subjectBox.Text, description, agentId);

                if (result.Success)
                {
                    _statusLabel.Text = "Ticket submitted!";
                    _statusLabel.ForeColor = Color.Green;
                    MessageBox.Show(
                        $"Your support ticket has been submitted successfully!\n\n" +
                        $"Subject: {_subjectBox.Text}\n" +
                        (result.TicketId.HasValue ? $"Ticket #: {result.TicketId}" : "") +
                        "\n\nOur team will respond shortly.",
                        "Ticket Submitted",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Information);
                    Close();
                    return;
                }
                else
                {
                    _statusLabel.Text = $"API Error: {result.Message}";
                    _statusLabel.ForeColor = Color.Red;
                }
            }
            else
            {
                // Fallback: save ticket locally and open email
                var ticketDir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "PCPlusSupport", "Tickets");
                Directory.CreateDirectory(ticketDir);

                var ticketFile = Path.Combine(ticketDir,
                    $"ticket_{DateTime.Now:yyyyMMdd_HHmmss}.txt");
                var content = $"Subject: {_subjectBox.Text}\nDate: {DateTime.Now}\n\n{description}";
                File.WriteAllText(ticketFile, content);

                // Copy screenshot to ticket folder if exists
                if (!string.IsNullOrEmpty(_screenshotPath) && File.Exists(_screenshotPath))
                {
                    var destFile = Path.Combine(ticketDir,
                        $"ticket_{DateTime.Now:yyyyMMdd_HHmmss}_{Path.GetFileName(_screenshotPath)}");
                    File.Copy(_screenshotPath, destFile, true);
                }

                _statusLabel.Text = "Ticket saved locally.";
                _statusLabel.ForeColor = Color.Green;
                MessageBox.Show(
                    $"Your ticket has been saved.\n\nFile: {ticketFile}\n\n" +
                    "Our team will review it shortly.",
                    "Ticket Saved",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
                Close();
            }

            _submitButton.Enabled = true;
        }
    }
}
