using Microsoft.ApplicationInsights;
using Microsoft.ApplicationInsights.DataContracts;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using System.Diagnostics;
using System.IO;
using System.Net.Sockets;

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
        private readonly int _licenseCheckIntervalSeconds;
        private readonly string _expectedWindowsEdition;
        private readonly string _kmsServer;
        private readonly int _kmsServerPort;
        private readonly string _kmsDnsEntry;

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

            // Windows license monitor config
            _licenseCheckIntervalSeconds = _configuration.GetValue<int>("WindowsLicenseMonitor:CheckIntervalSeconds", 3600);
            _expectedWindowsEdition = _configuration.GetValue<string>("WindowsLicenseMonitor:ExpectedEdition", "Enterprise");
            _kmsServer = _configuration.GetValue<string>("WindowsLicenseMonitor:KmsServer", null);
            _kmsServerPort = _configuration.GetValue<int>("WindowsLicenseMonitor:KmsServerPort", 1688);
            _kmsDnsEntry = _configuration.GetValue<string>("WindowsLicenseMonitor:KmsDnsEntry", "_vlmcs._tcp");

            // Enable Application Insights diagnostics
            EnableApplicationInsightsDiagnostics();
        }

        /// <summary>
        /// Enables Application Insights internal diagnostics logging to capture telemetry send errors.
        /// Errors will be logged using the provided ILogger and written to a file with timestamps.
        /// </summary>
        private void EnableApplicationInsightsDiagnostics()
        {
            // Read the log file path from configuration, fallback to default if not set
            var logFilePath = _configuration.GetValue<string>("LocalLog:FilePath") ?? "ai-internal.log";

            // Ensure the directory exists
            var logDir = Path.GetDirectoryName(logFilePath);
            if (!string.IsNullOrEmpty(logDir) && !Directory.Exists(logDir))
            {
                Directory.CreateDirectory(logDir);
            }

            // Add a timestamped trace listener for Application Insights internal logs
            if (!System.Diagnostics.Trace.Listeners.OfType<TimestampedTextWriterTraceListener>()
                .Any(l => l.Writer is StreamWriter sw && sw.BaseStream is FileStream fs && fs.Name == logFilePath))
            {
                System.Diagnostics.Trace.Listeners.Add(new TimestampedTextWriterTraceListener(logFilePath));
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
        /// Checks if the Windows edition matches the expected value, if the KMS server port is reachable,
        /// and if the DNS entry exists. Logs detailed errors locally and sends telemetry if any check fails.
        /// </summary>
        private void CheckWindowsEditionAndKms()
        {
            string edition = GetWindowsEdition();
            bool editionOk = edition.Equals(_expectedWindowsEdition, StringComparison.OrdinalIgnoreCase);

            bool kmsPortOk = true;
            string kmsPortError = null;
            if (!string.IsNullOrWhiteSpace(_kmsServer))
            {
                try
                {
                    using var client = new TcpClient();
                    var task = client.ConnectAsync(_kmsServer, _kmsServerPort);
                    if (!task.Wait(TimeSpan.FromSeconds(3)) || !client.Connected)
                    {
                        kmsPortOk = false;
                        kmsPortError = $"KMS server '{_kmsServer}' port {_kmsServerPort} not reachable (timeout or refused).";
                        _logger.LogError(kmsPortError);
                    }
                }
                catch (Exception ex)
                {
                    kmsPortOk = false;
                    kmsPortError = $"KMS server '{_kmsServer}' port {_kmsServerPort} check failed: {ex.Message}";
                    _logger.LogError(kmsPortError);
                }
            }

            bool dnsOk = true;
            string dnsError = null;
            if (!string.IsNullOrWhiteSpace(_kmsDnsEntry))
            {
                try
                {
                    var psi = new ProcessStartInfo
                    {
                        FileName = "nslookup",
                        Arguments = $"-type=all {_kmsDnsEntry}",
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    };
                    using var process = Process.Start(psi);
                    string output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();

                    if (!output.Contains(_kmsDnsEntry, StringComparison.OrdinalIgnoreCase) || output.Contains("***"))
                    {
                        dnsOk = false;
                        dnsError = $"DNS entry '{_kmsDnsEntry}' not found or invalid.";
                        _logger.LogError(dnsError);
                    }
                }
                catch (Exception ex)
                {
                    dnsOk = false;
                    dnsError = $"DNS entry '{_kmsDnsEntry}' check failed: {ex.Message}";
                    _logger.LogError(dnsError);
                }
            }

            if (!editionOk)
            {
                string editionError = $"Windows edition mismatch: Detected '{edition}', expected '{_expectedWindowsEdition}'.";
                _logger.LogError(editionError);
            }

            // Only send telemetry if edition is not as expected, KMS port check fails, or DNS check fails
            if (!editionOk || !kmsPortOk || !dnsOk)
            {
                string message = $"Windows license check: Edition: {edition} (expected: {_expectedWindowsEdition}), " +
                                 $"KMS Port: {(kmsPortOk ? "OK" : kmsPortError)}, DNS: {(dnsOk ? "OK" : dnsError)}";
                _logger.LogWarning(message);

                var telemetry = new EventTelemetry("WindowsLicenseCheckFailed")
                {
                    Timestamp = DateTimeOffset.Now
                };
                telemetry.Properties["DetectedEdition"] = edition;
                telemetry.Properties["ExpectedEdition"] = _expectedWindowsEdition;
                telemetry.Properties["KmsServer"] = _kmsServer ?? "";
                telemetry.Properties["KmsServerPort"] = _kmsServerPort.ToString();
                telemetry.Properties["KmsPortStatus"] = kmsPortOk ? "OK" : kmsPortError ?? "Unknown error";
                telemetry.Properties["KmsDnsEntry"] = _kmsDnsEntry ?? "";
                telemetry.Properties["KmsDnsStatus"] = dnsOk ? "OK" : dnsError ?? "Unknown error";

                _telemetryClient.TrackEvent(telemetry);
                _telemetryClient.Flush();
            }
        }

        /// <summary>
        /// Gets the Windows edition from the registry.
        /// </summary>
        private string GetWindowsEdition()
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
                return key?.GetValue("EditionID")?.ToString() ?? "Unknown";
            }
            catch
            {
                return "Unknown";
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
            var licenseCheckTimer = _licenseCheckIntervalSeconds;
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

                // Windows license check based on its own interval
                if (licenseCheckTimer <= 0)
                {
                    CheckWindowsEditionAndKms();
                    licenseCheckTimer = _licenseCheckIntervalSeconds;
                }

                await Task.Delay(TimeSpan.FromSeconds(1), stoppingToken);
                crashReportTimer--;
                licenseCheckTimer--;
            }
        }
    }
}
