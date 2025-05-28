using Microsoft.ApplicationInsights;
using Microsoft.ApplicationInsights.DataContracts;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System.Diagnostics;
using System.IO;

namespace EPNMonitoring
{
    public class Worker : BackgroundService
    {
        private readonly ILogger<Worker> _logger;
        private readonly TelemetryClient _telemetryClient;
        private readonly IConfiguration _configuration;
        private readonly int _checkIntervalSeconds;
        private readonly List<string> _executables;
        private readonly string _crashReportFolder;
        private readonly string _crashReportDestinationFolder;
        private readonly int _crashReportCheckIntervalSeconds;

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

            // Crash report monitor config
            _crashReportFolder = _configuration.GetValue<string>("CrashReportMonitor:FolderPath");
            _crashReportDestinationFolder = _configuration.GetValue<string>("CrashReportMonitor:DestinationFolder");
            _crashReportCheckIntervalSeconds = _configuration.GetValue<int>("CrashReportMonitor:CheckIntervalSeconds", 60);

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

                if (!isRunning)
                {
                    // Log locally
                    _logger.LogInformation("Process '{ProcessName}' is NOT running: {IsRunning}", exe, isRunning);

                    // Send custom event to Application Insights
                    var telemetry = new EventTelemetry("ProcessNotRunning")
                    {
                        Timestamp = DateTimeOffset.Now
                    };
                    telemetry.Properties["ProcessName"] = exe;
                    telemetry.Properties["IsRunning"] = isRunning.ToString();

                    _telemetryClient.TrackEvent(telemetry);
                }
            }

            // Flush telemetry (optional, for near real-time reporting)
            _telemetryClient.Flush();
        }

        /// <summary>
        /// Checks for crash reports in the configured folder, moves them if found, and logs/sends a single telemetry event per crash.
        /// A crash is identified by files sharing the same base filename (e.g., .dmp and .extra).
        /// </summary>
        private void CheckAndMoveCrashReports()
        {
            if (string.IsNullOrWhiteSpace(_crashReportFolder) || !Directory.Exists(_crashReportFolder))
            {
                _logger.LogWarning("Crash report folder does not exist: {FolderPath}", _crashReportFolder);
                return;
            }
            if (string.IsNullOrWhiteSpace(_crashReportDestinationFolder))
            {
                _logger.LogWarning("Crash report destination folder is not set.");
                return;
            }
            if (!Directory.Exists(_crashReportDestinationFolder))
            {
                Directory.CreateDirectory(_crashReportDestinationFolder);
            }

            var files = Directory.GetFiles(_crashReportFolder);

            // Group files by base filename (without extension)
            var crashGroups = files
                .Select(f => new FileInfo(f))
                .GroupBy(f => Path.GetFileNameWithoutExtension(f.Name));

            foreach (var group in crashGroups)
            {
                // Use the earliest creation time among the group as the crash time
                var firstFile = group.OrderBy(f => f.CreationTime).First();

                // Log and send telemetry only once per crash
                _logger.LogWarning("Crash report detected: {BaseName}, Created: {CreationTime}", group.Key, firstFile.CreationTime);

                var telemetry = new EventTelemetry("CrashReportDetected")
                {
                    Timestamp = DateTimeOffset.Now
                };
                telemetry.Properties["BaseName"] = group.Key;
                telemetry.Properties["CreationTime"] = firstFile.CreationTime.ToString("o");

                _telemetryClient.TrackEvent(telemetry);

                // Move all files in the group
                foreach (var file in group)
                {
                    var destPath = Path.Combine(_crashReportDestinationFolder, file.Name);
                    try
                    {
                        File.Move(file.FullName, destPath, overwrite: true);
                        _logger.LogInformation("Crash report file moved to: {Destination}", destPath);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Failed to move crash report file: {FileName}", file.Name);
                    }
                }
            }

            if (files.Length > 0)
            {
                _telemetryClient.Flush();
            }
        }

        /// <summary>
        /// Main execution loop for the background service.
        /// </summary>
        /// <param name="stoppingToken">Cancellation token.</param>
        /// <returns>Task</returns>
        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            var crashReportTimer = 0;
            while (!stoppingToken.IsCancellationRequested)
            {
                // Process monitor check
                CheckProcessesAndSendTelemetry();

                // Crash report check based on its own interval
                if (crashReportTimer <= 0)
                {
                    CheckAndMoveCrashReports();
                    crashReportTimer = _crashReportCheckIntervalSeconds;
                }

                await Task.Delay(TimeSpan.FromSeconds(1), stoppingToken);
                crashReportTimer--;
            }
        }
    }
}
