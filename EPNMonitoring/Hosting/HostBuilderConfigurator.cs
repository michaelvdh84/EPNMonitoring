using EPNMonitoring;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Hosting.WindowsServices;
using Microsoft.Extensions.Logging;

namespace EPNMonitoring.Hosting
{
    /// <summary>
    /// Provides a single entry point for configuring and building the <see cref="IHost"/>.
    /// </summary>
    public static class HostBuilderConfigurator
    {
        /// <summary>
        /// Builds a fully configured <see cref="IHost"/> for the application.
        /// </summary>
        /// <param name="args">Command-line arguments.</param>
        /// <returns>A configured <see cref="IHost"/> instance.</returns>
        public static IHost BuildHost(string[] args)
        {
            var builder = Host.CreateApplicationBuilder(args);

            ConfigureLogging(builder);
            ConfigureServices(builder);

            return builder.Build();
        }

        private static void ConfigureLogging(HostApplicationBuilder builder)
        {
            var localLogPath = builder.Configuration.GetValue<string>("LocalLog:FilePath");
            if (!string.IsNullOrWhiteSpace(localLogPath))
            {
                var fileLoggerProvider = new FileLoggerProvider(localLogPath);
                builder.Services.AddSingleton(fileLoggerProvider);
                builder.Logging.AddProvider(fileLoggerProvider);
            }
        }

        private static void ConfigureServices(HostApplicationBuilder builder)
        {
            builder.Services.AddWindowsService(options =>
            {
                options.ServiceName = "EPNMonitoring";
            });

            builder.Services.AddHostedService<Worker>();
            builder.Services.AddApplicationInsightsTelemetryWorkerService();
        }
    }
}
