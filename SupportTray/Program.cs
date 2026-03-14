using System;
using System.Windows.Forms;

namespace SupportTray
{
    static class Program
    {
        [STAThread]
        static void Main(string[] args)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            // Prevent multiple instances
            bool createdNew;
            using var mutex = new System.Threading.Mutex(true, "PCPlusSupportTray_SingleInstance", out createdNew);
            if (!createdNew)
            {
                MessageBox.Show("PC Plus Support is already running.", "PC Plus Support",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            Application.Run(new TrayApplicationContext());
        }
    }
}
