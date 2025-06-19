using Microsoft.ApplicationInsights;
using Microsoft.ApplicationInsights.DataContracts;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Net;
using System.Net.Sockets;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace EPNMonitoring
{
    public class Worker : BackgroundService
    {
        private readonly ILogger<Worker> _logger;
        private readonly TelemetryClient _telemetryClient;
        private readonly IConfiguration _configuration;

        // Process monitor
        private readonly int _checkIntervalSeconds;
        private readonly List<string> _executables;

        // Crash report monitor
        private readonly string _crashReportFolder;
        private readonly string _crashReportDestinationFolder;
        private readonly int _crashReportCheckIntervalSeconds;

        // Windows license monitor
        private readonly int _licenseCheckIntervalSeconds;
        private readonly string _expectedWindowsEdition;
        private readonly string _kmsServer;
        private readonly int _kmsServerPort;
        private readonly string _kmsDnsEntry;
        private readonly string _kmsKey;
        private readonly bool _enableActivation;
        private readonly bool _restartAfterActivation;

        // Website monitor
        private readonly int _websiteCheckIntervalSeconds;
        private readonly List<string> _websites;

        // Device monitor
        private readonly List<string> _devicesToCheck;
        private readonly int _deviceCheckIntervalSeconds;

        // Port tests monitor
        private readonly string _portTestServer;
        private readonly List<PortTestConfig> _portTests;
        private readonly int _portTestsCheckIntervalSeconds;

        // Verbose logging
        private readonly bool _verboseLoggingLocal;
        private readonly bool _verboseLoggingAppInsight;

        public Worker(
            ILogger<Worker> logger,
            TelemetryClient telemetryClient,
            IConfiguration configuration)
        {
            _logger = logger;
            _telemetryClient = telemetryClient;
            _configuration = configuration;

            // Process monitor config
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
            _kmsKey = _configuration.GetValue<string>("WindowsLicenseMonitor:KmsKey", null);
            _enableActivation = _configuration.GetValue<bool>("WindowsLicenseMonitor:EnableActivation", false);
            _restartAfterActivation = _configuration.GetValue<bool>("WindowsLicenseMonitor:RestartAfterActivation", false);

            // Website monitor config
            _websiteCheckIntervalSeconds = _configuration.GetValue<int>("WebsiteMonitor:CheckIntervalSeconds", 300);
            _websites = _configuration.GetSection("WebsiteMonitor:Sites").Get<List<string>>() ?? new List<string>();

            // Device monitor config
            _devicesToCheck = _configuration.GetSection("DeviceMonitor:Devices").Get<List<string>>() ?? new List<string>();
            _deviceCheckIntervalSeconds = _configuration.GetValue<int>("DeviceMonitor:CheckIntervalSeconds", 60);

            // Port tests monitor config
            var portTestsMonitorSection = _configuration.GetSection("PortTestsMonitor");
            _portTestServer = portTestsMonitorSection.GetValue<string>("LogonServer");
            _portTests = portTestsMonitorSection.GetSection("PortTests").Get<List<PortTestConfig>>() ?? new List<PortTestConfig>();
            _portTestsCheckIntervalSeconds = portTestsMonitorSection.GetValue<int>("CheckIntervalSeconds", 60);

            // Verbose logging config
            // Ensure _verboseLoggingLocal is always set from config
            _verboseLoggingLocal = _configuration.GetValue<bool>("VerboseLogging:Local", false);
            _verboseLoggingAppInsight = _configuration.GetValue<bool>("VerboseLogging:AppInsight", false);

            // Log the current verbose logging settings for diagnostics
            if (_verboseLoggingLocal)
                _logger.LogInformation("Verbose local logging is ENABLED by configuration.");
            else
                _logger.LogInformation("Verbose local logging is DISABLED by configuration.");

            EnableApplicationInsightsDiagnostics();
        }

        /// <summary>
        /// Enables Application Insights internal diagnostics logging.
        /// </summary>
        private void EnableApplicationInsightsDiagnostics()
        {
            try
            {
                var logFilePath = _configuration.GetValue<string>("LocalLog:FilePath") ?? "ai-internal.log";
                var logDir = Path.GetDirectoryName(logFilePath);
                if (!string.IsNullOrEmpty(logDir) && !Directory.Exists(logDir))
                {
                    Directory.CreateDirectory(logDir);
                }

                // Extra diagnostics: log file path and directory existence
                if (_verboseLoggingLocal)
                    _logger.LogInformation("Attempting to initialize local log file at: {LogFilePath}", logFilePath);
                if (!Directory.Exists(logDir))
                {
                    if (_verboseLoggingLocal)
                        _logger.LogWarning("Log directory does not exist after creation attempt: {LogDir}", logDir);
                }

                if (!System.Diagnostics.Trace.Listeners.OfType<TimestampedTextWriterTraceListener>()
                    .Any(l => l.Writer is StreamWriter sw && sw.BaseStream is FileStream fs && fs.Name == logFilePath))
                {
                    System.Diagnostics.Trace.Listeners.Add(new TimestampedTextWriterTraceListener(logFilePath));
                    System.Diagnostics.Trace.AutoFlush = true;
                    if (_verboseLoggingLocal)
                        _logger.LogInformation("Local log file listener added successfully: {LogFilePath}", logFilePath);
                }
                else
                {
                    if (_verboseLoggingLocal)
                        _logger.LogInformation("Local log file listener already exists for: {LogFilePath}", logFilePath);
                }

                // Test write to log file
                System.Diagnostics.Trace.WriteLine("Local log file initialized successfully.");
            }
            catch (Exception ex)
            {
                // Fallback: log to Windows Event Log if file cannot be created
                try
                {
                    EventLog.WriteEntry("EPNMonitoring", $"Failed to initialize local log file: {ex}", EventLogEntryType.Error);
                }
                catch
                {
                    // Swallow to avoid recursive errors
                }
                // Also log to ILogger for visibility
                _logger.LogError(ex, "Exception occurred while initializing local log file.");
            }
        }

        /// <summary>
        /// Helper to track telemetry events respecting verbose logging settings.
        /// Informational events are only sent when AppInsight verbose logging is enabled.
        /// Warning and error events are always sent.
        /// </summary>
        private void TrackTelemetryEvent(string eventName, IDictionary<string, string?> properties, bool isInformational)
        {
            if (!isInformational || _verboseLoggingAppInsight)
            {
                var telemetry = new EventTelemetry(eventName)
                {
                    Timestamp = System.DateTimeOffset.Now
                };
                foreach (var kvp in properties)
                {
                    telemetry.Properties[kvp.Key] = kvp.Value ?? string.Empty;
                }
                _telemetryClient.TrackEvent(telemetry);
                _telemetryClient.Flush();
            }
        }

        /// <summary>
        /// Checks if the specified processes are running and sends the result to Application Insights.
        /// </summary>
        private void CheckProcessesAndSendTelemetry()
        {
            foreach (var exe in _executables)
            {
                var processName = exe.EndsWith(".exe", System.StringComparison.OrdinalIgnoreCase)
                    ? exe[..^4]
                    : exe;

                var isRunning = Process.GetProcessesByName(processName).Any();

                if (!isRunning)
                {
                    if (_verboseLoggingLocal)
                        _logger.LogInformation("Process '{ProcessName}' is NOT running: {IsRunning}", exe, isRunning);
                    _logger.LogWarning("Process '{ProcessName}' is NOT running!", exe);

                    TrackTelemetryEvent(
                        "ProcessNotRunning",
                        new Dictionary<string, string?>
                        {
                            ["ProcessName"] = exe,
                            ["IsRunning"] = isRunning.ToString()
                        },
                        isInformational: false);
                }
                else
                {
                    if (_verboseLoggingLocal)
                        _logger.LogInformation("Process '{ProcessName}' is running.", exe);

                    TrackTelemetryEvent(
                        "ProcessRunning",
                        new Dictionary<string, string?>
                        {
                            ["ProcessName"] = exe,
                            ["IsRunning"] = isRunning.ToString()
                        },
                        isInformational: true);
                }
            }
        }

        /// <summary>
        /// Checks for crash reports in the configured folder, moves them if found, and logs/sends a single telemetry event per crash.
        /// </summary>
        private void CheckAndMoveCrashReports()
        {
            if (string.IsNullOrWhiteSpace(_crashReportFolder) || !Directory.Exists(_crashReportFolder))
            {
                if (_verboseLoggingLocal)
                    _logger.LogWarning("Crash report folder does not exist: {FolderPath}", _crashReportFolder);

                TrackTelemetryEvent(
                    "CrashReportFolderMissing",
                    new Dictionary<string, string?> { ["FolderPath"] = _crashReportFolder },
                    isInformational: false);
                return;
            }
            if (string.IsNullOrWhiteSpace(_crashReportDestinationFolder))
            {
                if (_verboseLoggingLocal)
                    _logger.LogWarning("Crash report destination folder is not set.");

                TrackTelemetryEvent(
                    "CrashReportDestinationMissing",
                    new Dictionary<string, string?>(),
                    isInformational: false);
                return;
            }
            if (!Directory.Exists(_crashReportDestinationFolder))
                Directory.CreateDirectory(_crashReportDestinationFolder);

            var files = Directory.GetFiles(_crashReportFolder);
            var crashGroups = files
                .Select(f => new FileInfo(f))
                .GroupBy(f => Path.GetFileNameWithoutExtension(f.Name));

            foreach (var group in crashGroups)
            {
                var firstFile = group.OrderBy(f => f.CreationTime).First();

                _logger.LogWarning("Crash report detected: {BaseName}, Created: {CreationTime}", group.Key, firstFile.CreationTime);

                TrackTelemetryEvent(
                    "CrashReportDetected",
                    new Dictionary<string, string?>
                    {
                        ["BaseName"] = group.Key,
                        ["CreationTime"] = firstFile.CreationTime.ToString("o")
                    },
                    isInformational: false);

                foreach (var file in group)
                {
                    var destPath = Path.Combine(_crashReportDestinationFolder, file.Name);
                    try
                    {
                        File.Move(file.FullName, destPath, overwrite: true);
                        if (_verboseLoggingLocal)
                            _logger.LogInformation("Crash report file moved to: {Destination}", destPath);
                    }
                    catch (System.Exception ex)
                    {
                        _logger.LogError(ex, "Failed to move crash report file: {FileName}", file.Name);
                    }
                }
            }

            // Flushing handled by TrackTelemetryEvent
        }

        /// <summary>
        /// Checks if the specified devices are present and sends the result to Application Insights.
        /// </summary>
        private void CheckDevicesAndSendTelemetry()
        {
            var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_PnPEntity");
            var devices = searcher.Get().Cast<ManagementObject>()
                .Select(mo => mo["Name"]?.ToString() ?? string.Empty)
                .ToList();

            if (_verboseLoggingLocal)
            {
                _logger.LogInformation("Device check started. Configured devices to check: {Count}", _devicesToCheck.Count);
                _logger.LogInformation("Detected devices from Win32_PnPEntity: {DeviceList}", string.Join("; ", devices));
            }

            int foundCount = 0, missingCount = 0;

            foreach (var deviceName in _devicesToCheck)
            {
                bool found = devices.Any(d => d.Contains(deviceName, System.StringComparison.OrdinalIgnoreCase));
                if (!found)
                {
                    _logger.LogWarning("Device not found: {DeviceName}", deviceName);
                    missingCount++;
                    TrackTelemetryEvent(
                        "DeviceNotFound",
                        new Dictionary<string, string?> { ["DeviceName"] = deviceName },
                        isInformational: false);
                }
                else
                {
                    foundCount++;
                    if (_verboseLoggingLocal)
                        _logger.LogInformation("Device found: {DeviceName}", deviceName);
                }
            }

            if (_verboseLoggingLocal)
                _logger.LogInformation("Device check summary: {Found} found, {Missing} missing, {Total} total.", foundCount, missingCount, _devicesToCheck.Count);

            // Flushing handled by TrackTelemetryEvent
        }

        /// <summary>
        /// Checks if the specified server ports are open and sends the result to Application Insights.
        /// </summary>
        private void CheckServerPortsAndSendTelemetry()
        {
            if (string.IsNullOrWhiteSpace(_portTestServer))
            {
                _logger.LogWarning("No server specified for port tests.");
                TrackTelemetryEvent(
                    "PortTestServerNotSpecified",
                    new Dictionary<string, string?> { ["Reason"] = "No server specified in configuration." },
                    isInformational: false);
                return;
            }

            if (_verboseLoggingLocal)
                _logger.LogInformation("Checking ports on server: {Server}", _portTestServer);

            foreach (var test in _portTests)
            {
                string result;
                try
                {
                    using var client = new TcpClient();
                    var connectTask = client.ConnectAsync(_portTestServer, test.Port);
                    if (connectTask.Wait(System.TimeSpan.FromSeconds(3)) && client.Connected)
                    {
                        result = "OPEN";
                        if (_verboseLoggingLocal)
                            _logger.LogInformation("Port '{Title}' ({Port}) on {Server}: OPEN", test.Title, test.Port, _portTestServer);
                            TrackTelemetryEvent(
                                "PortTestOpened",
                                new Dictionary<string, string?> {
                                    ["Title"] = test.Title,
                                    ["Port"] = test.Port.ToString(),
                                    ["Server"] = _portTestServer,
                                    ["Result"] = result
                                },
                        isInformational: true);
                    }
                    else
                    {
                        result = "CLOSED or TIMEOUT";
                        _logger.LogWarning("Port '{Title}' ({Port}) on {Server}: CLOSED or TIMEOUT", test.Title, test.Port, _portTestServer);
                        TrackTelemetryEvent(
                            "PortTestTimeoutOrClosed",
                            new Dictionary<string, string?>
                            {
                                ["Title"] = test.Title,
                                ["Port"] = test.Port.ToString(),
                                ["Server"] = _portTestServer,
                                ["Result"] = result
                            },
                            isInformational: false);
                    }
                }
                catch (System.Exception ex)
                {
                    result = "ERROR";
                    _logger.LogError(ex, "Port '{Title}' ({Port}) on {Server}: ERROR", test.Title, test.Port, _portTestServer);
                }

                //bool isInformational = result == "OPEN";
                //TrackTelemetryEvent(
                //    "ServerPortTest",
                //    new Dictionary<string, string?>
                //    {
                //        ["Server"] = _portTestServer,
                //        ["Title"] = test.Title,
                //        ["Port"] = test.Port.ToString(),
                //        ["Result"] = result
                //    },
                //    isInformational: isInformational);
            }

            // Flushing handled by TrackTelemetryEvent
        }

        /// <summary>
        /// Checks connectivity to each website specified in the configuration.
        /// Logs locally and sends telemetry if a site is unreachable.
        /// </summary>
        private async Task CheckWebsitesConnectivityAsync()
        {
            foreach (var site in _websites)
            {
                try
                {
                    using var httpClient = new System.Net.Http.HttpClient();
                    httpClient.Timeout = System.TimeSpan.FromSeconds(5);
                    var response = await httpClient.GetAsync(site);
                    if (!response.IsSuccessStatusCode)
                    {
                        _logger.LogWarning("Website unreachable (HTTP {StatusCode}): {Site}", (int)response.StatusCode, site);
                        SendWebsiteUnreachableTelemetry(site, $"HTTP {(int)response.StatusCode}");
                    }
                    else
                    {
                        if (_verboseLoggingLocal)
                            _logger.LogInformation("Website reachable: {Site}", site);

                        TrackTelemetryEvent(
                            "WebsiteReachable",
                            new Dictionary<string, string?>
                            {
                                ["Site"] = site,
                                ["StatusCode"] = ((int)response.StatusCode).ToString()
                            },
                            isInformational: true);
                    }
                }
                catch (System.Exception ex)
                {
                    _logger.LogError(ex, "Website unreachable: {Site}", site);
                    SendWebsiteUnreachableTelemetry(site, ex.Message);
                }
            }
            // Flushing handled by TrackTelemetryEvent and SendWebsiteUnreachableTelemetry
        }

        /// <summary>
        /// Sends telemetry to Application Insights for unreachable websites.
        /// </summary>
        private void SendWebsiteUnreachableTelemetry(string site, string reason)
        {
            TrackTelemetryEvent(
                "WebsiteUnreachable",
                new Dictionary<string, string?>
                {
                    ["Site"] = site,
                    ["Reason"] = reason
                },
                isInformational: false);
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
        /// Attempts to activate Windows if the edition is 'Pro' and restarts the computer if configured.
        /// </summary>
        private void TryActivateWindowsIfProAndRestart()
        {
            string edition = GetWindowsEdition();
            if (!_enableActivation)
            {
                if (_verboseLoggingLocal)
                    _logger.LogInformation("Windows activation is disabled by configuration.");
                return;
            }

            if (!string.Equals(edition, "Pro", StringComparison.OrdinalIgnoreCase))
            {
                if (_verboseLoggingLocal)
                    _logger.LogInformation("Windows edition is not 'Pro' (detected: {Edition}), skipping activation.", edition);
                return;
            }

            if (string.IsNullOrWhiteSpace(_kmsKey))
            {
                _logger.LogWarning("No KMS key specified in configuration. Skipping activation attempt.");
                return;
            }

            if (_verboseLoggingLocal)
                _logger.LogInformation("Attempting Windows activation for 'Pro' edition with KMS key.");

            // Run slmgr.vbs activation
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "cscript",
                    Arguments = $"//Nologo %windir%\\system32\\slmgr.vbs /ipk {_kmsKey}",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using (var process = Process.Start(psi))
                {
                    string output = process.StandardOutput.ReadToEnd();
                    string error = process.StandardError.ReadToEnd();
                    process.WaitForExit();

                    if (_verboseLoggingLocal)
                        _logger.LogInformation("slmgr.vbs /ipk output: {Output} {Error}", output, error);

                    TrackTelemetryEvent(
                        "WindowsActivationAttempt",
                        new Dictionary<string, string?>
                        {
                            ["Edition"] = edition,
                            ["KMSKey"] = _kmsKey,
                            ["Output"] = output,
                            ["Error"] = error
                        },
                        isInformational: true);
                }

                // Activate
                psi.Arguments = "//Nologo %windir%\\system32\\slmgr.vbs /ato";
                using (var process = Process.Start(psi))
                {
                    string output = process.StandardOutput.ReadToEnd();
                    string error = process.StandardError.ReadToEnd();
                    process.WaitForExit();

                    if (_verboseLoggingLocal)
                        _logger.LogInformation("slmgr.vbs /ato output: {Output} {Error}", output, error);

                    TrackTelemetryEvent(
                        "WindowsActivationResult",
                        new Dictionary<string, string?>
                        {
                            ["Edition"] = edition,
                            ["Output"] = output,
                            ["Error"] = error
                        },
                        isInformational: true);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to activate Windows with KMS key.");
                TrackTelemetryEvent(
                    "WindowsActivationException",
                    new Dictionary<string, string?>
                    {
                        ["Edition"] = edition,
                        ["Exception"] = ex.Message
                    },
                    isInformational: false);
                return;
            }

            // Restart if configured
            if (_restartAfterActivation)
            {
                if (_verboseLoggingLocal)
                    _logger.LogInformation("Restarting computer after activation as configured.");
                TrackTelemetryEvent(
                    "WindowsRestartAfterActivation",
                    new Dictionary<string, string?>
                    {
                        ["Reason"] = "Activation completed and restart requested by configuration."
                    },
                    isInformational: true);
                try
                {
                    Process.Start(new ProcessStartInfo("shutdown", "/r /t 5")
                    {
                        CreateNoWindow = true,
                        UseShellExecute = false
                    });
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to restart the computer after activation.");
                }
            }
        }

        /// <summary>
        /// Cleans the local log file if it exceeds the maximum size and autoclean is enabled.
        /// </summary>
        private void CleanLocalLogIfNeeded()
        {
            var logSection = _configuration.GetSection("LocalLog");
            string logPath = logSection.GetValue<string>("FilePath");
            long maxSize = logSection.GetValue<long>("MaxLogSize", 10485760); // Default 10 MB
            bool autoclean = logSection.GetValue<bool>("Autoclean", false);

            if (string.IsNullOrWhiteSpace(logPath) || !File.Exists(logPath) || !autoclean)
                return;

            var fileInfo = new FileInfo(logPath);
            if (fileInfo.Length > maxSize)
            {
                try
                {
                    File.WriteAllText(logPath, string.Empty);
                    _logger.LogWarning("Local log file exceeded {MaxLogSize} bytes and was cleaned.", maxSize);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to clean local log file: {LogPath}", logPath);
                }
            }
        }

        /// <summary>
        /// Main execution loop for the background service.
        /// </summary>
        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            var crashReportTimer = 0;
            var licenseCheckTimer = _licenseCheckIntervalSeconds;
            var websiteCheckTimer = _websiteCheckIntervalSeconds;
            var processCheckTimer = _checkIntervalSeconds;
            var deviceCheckTimer = _deviceCheckIntervalSeconds;
            var portTestsCheckTimer = _portTestsCheckIntervalSeconds;
            var cleanLocalLogTimer = 3600;

            while (!stoppingToken.IsCancellationRequested)
            {
                if (processCheckTimer <= 0)
                {
                    CheckProcessesAndSendTelemetry();
                    processCheckTimer = _checkIntervalSeconds;
                }

                if (crashReportTimer <= 0)
                {
                    CheckAndMoveCrashReports();
                    crashReportTimer = _crashReportCheckIntervalSeconds;
                }

                if (licenseCheckTimer <= 0)
                {
                    GetWindowsEdition();
                    licenseCheckTimer = _licenseCheckIntervalSeconds;
                }

                if (websiteCheckTimer <= 0)
                {
                    await CheckWebsitesConnectivityAsync();
                    websiteCheckTimer = _websiteCheckIntervalSeconds;
                }

                if (deviceCheckTimer <= 0)
                {
                    CheckDevicesAndSendTelemetry();
                    deviceCheckTimer = _deviceCheckIntervalSeconds;
                }

                if (portTestsCheckTimer <= 0)
                {
                    CheckServerPortsAndSendTelemetry();
                    portTestsCheckTimer = _portTestsCheckIntervalSeconds;
                }

                if (licenseCheckTimer <= 0)
                {
                    //CheckWindowsEditionAndKms();
                    TryActivateWindowsIfProAndRestart();
                    licenseCheckTimer = _licenseCheckIntervalSeconds;
                }

                if (cleanLocalLogTimer <= 0)
                {
                    CleanLocalLogIfNeeded();
                    cleanLocalLogTimer = 3600;
                }

                //CleanLocalLogIfNeeded();

                await Task.Delay(System.TimeSpan.FromSeconds(1), stoppingToken);
                crashReportTimer--;
                licenseCheckTimer--;
                websiteCheckTimer--;
                processCheckTimer--;
                deviceCheckTimer--;
                licenseCheckTimer--;
                portTestsCheckTimer--;
            }
        }

        // The CheckWindowsEditionAndKms and TryActivateWindowsWithKmsKey methods are unchanged for brevity.
    }
}
