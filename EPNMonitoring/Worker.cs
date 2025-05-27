using Microsoft.ApplicationInsights;
using Microsoft.ApplicationInsights.DataContracts;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System.Diagnostics;

namespace EPNMonitoring
{
    public class Worker : BackgroundService
    {
        private readonly ILogger<Worker> _logger;
        private readonly TelemetryClient _telemetryClient;
        private readonly IConfiguration _configuration;
        private readonly int _checkIntervalSeconds;
        private readonly List<string> _executables;

        public Worker(
            ILogger<Worker> logger,
            TelemetryClient telemetryClient,
            IConfiguration configuration)
        {
            _logger = logger;
            _telemetryClient = telemetryClient;
            _configuration = configuration;

            _checkIntervalSeconds = _configuration.GetValue<int>("ProcessMonitor:CheckIntervalSeconds", 10);
            _executables = _configuration.GetSection("ProcessMonitor:Executables").Get<List<string>>() ?? new List<string>();

            // Enable Application Insights diagnostics
            EnableApplicationInsightsDiagnostics();
        }

        /// <summary>
        /// Enables Application Insights internal diagnostics logging to capture telemetry send errors.
        /// Errors will be logged using the provided ILogger and written to a file.
        /// </summary>
        private void EnableApplicationInsightsDiagnostics()
        {
            // Write Application Insights internal logs to a file for diagnostics
            var logFilePath = "ai-internal.log";
            if (!System.Diagnostics.Trace.Listeners.OfType<System.Diagnostics.TextWriterTraceListener>().Any(l => l.Writer is StreamWriter sw && sw.BaseStream is FileStream fs && fs.Name == logFilePath))
            {
                System.Diagnostics.Trace.Listeners.Add(new System.Diagnostics.TextWriterTraceListener(logFilePath));
                System.Diagnostics.Trace.AutoFlush = true;
            }
        }

        /// <summary>
        /// Checks if the specified processes are running and sends the result to Application Insights.
        /// </summary>
        private void CheckProcessesAndSendTelemetry()
        {
            foreach (var exe in _executables)
            {
                // Get all processes with the specified name (without .exe extension)
                var processName = exe.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
                    ? exe[..^4]
                    : exe;

                var isRunning = Process.GetProcessesByName(processName).Any();

                // Log locally
                _logger.LogInformation("Process '{ProcessName}' running: {IsRunning}", exe, isRunning);

                // Send custom event to Application Insights
                var telemetry = new EventTelemetry("ProcessCheck")
                {
                    Timestamp = DateTimeOffset.Now
                };
                telemetry.Properties["ProcessName"] = exe;
                telemetry.Properties["IsRunning"] = isRunning.ToString();

                _telemetryClient.TrackEvent(telemetry);
            }

            // Flush telemetry (optional, for near real-time reporting)
            _telemetryClient.Flush();
        }

        /// <summary>
        /// Main execution loop for the background service.
        /// </summary>
        /// <param name="stoppingToken">Cancellation token.</param>
        /// <returns>Task</returns>
        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                CheckProcessesAndSendTelemetry();
                await Task.Delay(TimeSpan.FromSeconds(_checkIntervalSeconds), stoppingToken);
            }
        }
    }
}
