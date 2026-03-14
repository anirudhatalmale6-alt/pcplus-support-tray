using System;
using System.Drawing;
using System.Windows.Forms;

namespace SupportTray
{
    public class SystemInfoForm : Form
    {
        private readonly AppConfig _config;

        public SystemInfoForm(AppConfig config)
        {
            _config = config;
            InitializeUI();
        }

        private void InitializeUI()
        {
            Text = $"{_config.CompanyName} - System Information";
            Size = new Size(500, 480);
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
                Height = 50,
                BackColor = Color.FromArgb(0, 120, 212)
            };
            var headerLabel = new Label
            {
                Text = "  System Information",
                ForeColor = Color.White,
                Font = new Font("Segoe UI", 14, FontStyle.Bold),
                AutoSize = false,
                Size = new Size(450, 35),
                Location = new Point(10, 8),
                TextAlign = ContentAlignment.MiddleLeft
            };
            header.Controls.Add(headerLabel);
            Controls.Add(header);

            // Info text box
            var infoBox = new RichTextBox
            {
                Location = new Point(15, 65),
                Size = new Size(455, 320),
                ReadOnly = true,
                BorderStyle = BorderStyle.FixedSingle,
                Font = new Font("Consolas", 9.5f),
                BackColor = Color.FromArgb(245, 245, 245),
                Text = "Loading system information..."
            };
            Controls.Add(infoBox);

            // Buttons
            var copyButton = new Button
            {
                Text = "Copy to Clipboard",
                Location = new Point(140, 395),
                Size = new Size(130, 35),
                BackColor = Color.FromArgb(0, 120, 212),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Cursor = Cursors.Hand
            };
            copyButton.FlatAppearance.BorderSize = 0;
            copyButton.Click += (s, e) =>
            {
                Clipboard.SetText(infoBox.Text);
                MessageBox.Show("System information copied to clipboard.", "Copied",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
            };
            Controls.Add(copyButton);

            var closeButton = new Button
            {
                Text = "Close",
                Location = new Point(280, 395),
                Size = new Size(100, 35),
                FlatStyle = FlatStyle.Flat,
                Cursor = Cursors.Hand
            };
            closeButton.Click += (s, e) => Close();
            Controls.Add(closeButton);

            // Load info async
            Load += async (s, e) =>
            {
                await System.Threading.Tasks.Task.Run(() =>
                {
                    var info = SystemInfo.GetFullReport();
                    Invoke(() => infoBox.Text = info);
                });
            };
        }
    }
}
