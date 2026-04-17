using System;
using System.Windows.Forms;

namespace PCPlus.Tray
{
    static class Program
    {
        [STAThread]
        static void Main(string[] args)
        {
            // DPI awareness for proper scaling on high-DPI displays
            Application.SetHighDpiMode(HighDpiMode.PerMonitorV2);
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            // Prevent multiple instances
            bool createdNew;
            using var mutex = new System.Threading.Mutex(true, "PCPlusEndpoint_Tray", out createdNew);
            if (!createdNew)
            {
                MessageBox.Show("PC Plus Endpoint Protection is already running.", "PC Plus",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            Application.Run(new TrayContext());
        }
    }
}
