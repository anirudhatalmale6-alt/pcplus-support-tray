using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using PCPlus.Service.Engine;

namespace PCPlus.Service
{
    /// <summary>
    /// Windows Service entry point.
    /// Install: sc create PCPlusEndpoint binPath="C:\...\PCPlusService.exe" start=auto
    /// Or run as console app for debugging.
    /// </summary>
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = Host.CreateApplicationBuilder(args);

            // Register our service
            builder.Services.AddWindowsService(options =>
            {
                options.ServiceName = "PCPlusEndpoint";
            });

            builder.Services.AddSingleton<ServiceConfig>(_ => ServiceConfig.Load());
            builder.Services.AddSingleton<ModuleEngine>();
            builder.Services.AddHostedService<EndpointProtectionService>();

            var host = builder.Build();
            host.Run();
        }
    }
}
