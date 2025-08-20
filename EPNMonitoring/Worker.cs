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
using System.Diagnostics.Eventing.Reader;
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
        private readonly List<PortTestServerConfig> _portTestServers;
        private readonly int _portTestsCheckIntervalSeconds;

        // Event viewer monitor
        private readonly int _eventViewerCheckIntervalSeconds;
        private readonly List<string> _eventViewerApplications;
        private DateTime _lastEventViewerCheck;

        // Verbose logging
        private readonly bool _verboseLoggingLocal;
        private readonly bool _verboseLoggingAppInsight;

        // Kiosk user
        private readonly string _kioskUser;

        // Kiosk user check interval and list
        private readonly int _kioskUserCheckIntervalSeconds;
        private readonly List<string> _kioskUsers;

        private readonly bool _processMonitorEnabled;
        private readonly bool _crashReportMonitorEnabled;
        private readonly bool _windowsLicenseMonitorEnabled;
        private readonly bool _localLogEnabled;
        private readonly bool _websiteMonitorEnabled;
        private readonly bool _eventViewerMonitorEnabled;
        private readonly bool _deviceMonitorEnabled;
        private readonly bool _portTestsMonitorEnabled;
        private readonly bool _kioskUserEnabled;

        // Default printer settings
        private readonly bool _defaultPrinterEnabled;
        private readonly string _defaultPrinterName;
        private readonly int _defaultPrinterCheckIntervalSeconds;
        private readonly bool _defaultPrinterForceDefault;

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
            _portTestServers = portTestsMonitorSection.GetSection("Servers").Get<List<PortTestServerConfig>>() ?? new List<PortTestServerConfig>();
            _portTestsCheckIntervalSeconds = portTestsMonitorSection.GetValue<int>("CheckIntervalSeconds", 60);

            // Event viewer monitor config
            var eventViewerSection = _configuration.GetSection("EventViewerMonitor");
            _eventViewerCheckIntervalSeconds = eventViewerSection.GetValue<int>("CheckIntervalSeconds", 300);
            _eventViewerApplications = eventViewerSection.GetSection("Applications").Get<List<string>>() ?? new List<string>();
            _lastEventViewerCheck = DateTime.MinValue;

            // Verbose logging config
            // Ensure _verboseLoggingLocal is always set from config
            _verboseLoggingLocal = _configuration.GetValue<bool>("VerboseLogging:Local", false);
            _verboseLoggingAppInsight = _configuration.GetValue<bool>("VerboseLogging:AppInsight", false);

            // Kiosk user config
            _kioskUser = _configuration.GetValue<string>("KioskUser");

            // Kiosk user check interval and list config
            var kioskUserSection = _configuration.GetSection("KioskUser");
            _kioskUserCheckIntervalSeconds = kioskUserSection.GetValue<int>("CheckIntervalSeconds", 60);
            _kioskUsers = kioskUserSection.GetSection("Users").Get<List<string>>() ?? new List<string>();

            // Log the current verbose logging settings for diagnostics
            if (_verboseLoggingLocal)
                _logger.LogInformation("Verbose local logging is ENABLED by configuration.");
            else
                _logger.LogInformation("Verbose local logging is DISABLED by configuration.");

            EnableApplicationInsightsDiagnostics();

            _processMonitorEnabled = _configuration.GetValue<bool>("ProcessMonitor:Enabled", true);
            _crashReportMonitorEnabled = _configuration.GetValue<bool>("CrashReportMonitor:Enabled", true);
            _windowsLicenseMonitorEnabled = _configuration.GetValue<bool>("WindowsLicenseMonitor:Enabled", true);
            _localLogEnabled = _configuration.GetValue<bool>("LocalLog:Enabled", true);
            _websiteMonitorEnabled = _configuration.GetValue<bool>("WebsiteMonitor:Enabled", true);
            _eventViewerMonitorEnabled = _configuration.GetValue<bool>("EventViewerMonitor:Enabled", true);
            _deviceMonitorEnabled = _configuration.GetValue<bool>("DeviceMonitor:Enabled", true);
            _portTestsMonitorEnabled = _configuration.GetValue<bool>("PortTestsMonitor:Enabled", true);
            _kioskUserEnabled = _configuration.GetValue<bool>("KioskUser:Enabled", true);

            // Default printer settings
            var defaultPrinterSection = _configuration.GetSection("DefaultPrinter");
            _defaultPrinterEnabled = defaultPrinterSection.GetValue<bool>("Enabled", true);
            _defaultPrinterName = defaultPrinterSection.GetValue<string>("Name", "");
            _defaultPrinterCheckIntervalSeconds = defaultPrinterSection.GetValue<int>("CheckIntervalSeconds", 60);
            _defaultPrinterForceDefault = defaultPrinterSection.GetValue<bool>("ForceDefault", false);
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
        /// Checks the Windows event log for application errors of the configured applications.
        /// Logs locally and sends telemetry when matching events are found.
        /// </summary>
        private void CheckEventViewerForApplicationErrors()
        {
            if (_eventViewerApplications.Count == 0)
                return;

            string query = "*[System[(EventID=1000 and Provider[@Name='Application Error'])]]";
            var logQuery = new EventLogQuery("Application", PathType.LogName, query);

            try
            {
                using var reader = new EventLogReader(logQuery);
                for (EventRecord? record = reader.ReadEvent(); record != null; record = reader.ReadEvent())
                {
                    if (record.TimeCreated == null || record.TimeCreated <= _lastEventViewerCheck)
                        continue;

                    string appName = record.Properties.Count > 0 ? record.Properties[0]?.Value?.ToString() ?? string.Empty : string.Empty;
                    string appVersion = record.Properties.Count > 1 ? record.Properties[1]?.Value?.ToString() ?? string.Empty : string.Empty;
                    string moduleName = record.Properties.Count > 2 ? record.Properties[2]?.Value?.ToString() ?? string.Empty : string.Empty;

                    if (_eventViewerApplications.Any(a => appName.Contains(a, System.StringComparison.OrdinalIgnoreCase)))
                    {
                        _logger.LogError("Application error detected: {AppName} {AppVersion} in {ModuleName} at {Time}",
                            appName, appVersion, moduleName, record.TimeCreated);

                        TrackTelemetryEvent(
                            "EventViewerApplicationError",
                            new Dictionary<string, string?>
                            {
                                ["AppName"] = appName,
                                ["AppVersion"] = appVersion,
                                ["ModuleName"] = moduleName,
                                ["SystemTime"] = record.TimeCreated?.ToString("o")
                            },
                            isInformational: false);
                    }
                }
            }
            catch (EventLogException ex)
            {
                _logger.LogError(ex, "Failed to read event log for application errors.");
            }
            finally
            {
                _lastEventViewerCheck = System.DateTime.Now;
            }
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
            if (_portTestServers == null || _portTestServers.Count == 0)
            {
                _logger.LogWarning("No servers specified for port tests.");
                TrackTelemetryEvent(
                    "PortTestServersNotSpecified",
                    new Dictionary<string, string?> { ["Reason"] = "No servers specified in configuration." },
                    isInformational: false);
                return;
            }

            foreach (var server in _portTestServers)
            {
                if (_verboseLoggingLocal)
                    _logger.LogInformation("Checking ports on server: {Server}", server.Name);

                foreach (var port in server.Ports)
                {
                    string result;
                    try
                    {
                        using var client = new TcpClient();
                        var connectTask = client.ConnectAsync(server.Name, port);
                        if (connectTask.Wait(TimeSpan.FromSeconds(3)) && client.Connected)
                        {
                            result = "OPEN";
                            if (_verboseLoggingLocal)
                                _logger.LogInformation("Port {Port} on {Server}: OPEN", port, server.Name);
                            TrackTelemetryEvent(
                                "PortTestOpened",
                                new Dictionary<string, string?>
                                {
                                    ["Port"] = port.ToString(),
                                    ["Server"] = server.Name,
                                    ["Result"] = result
                                },
                                isInformational: true);
                        }
                        else
                        {
                            result = "CLOSED or TIMEOUT";
                            _logger.LogWarning("Port {Port} on {Server}: CLOSED or TIMEOUT", port, server.Name);
                            TrackTelemetryEvent(
                                "PortTestTimeoutOrClosed",
                                new Dictionary<string, string?>
                                {
                                    ["Port"] = port.ToString(),
                                    ["Server"] = server.Name,
                                    ["Result"] = result
                                },
                                isInformational: false);
                        }
                    }
                    catch (Exception ex)
                    {
                        result = "ERROR";
                        _logger.LogError(ex, "Port {Port} on {Server}: ERROR", port, server.Name);
                        TrackTelemetryEvent(
                            "PortTestError",
                            new Dictionary<string, string?>
                            {
                                ["Port"] = port.ToString(),
                                ["Server"] = server.Name,
                                ["Result"] = result,
                                ["Error"] = ex.Message
                            },
                            isInformational: false);
                    }
                }
            }
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
        /// Checks the current Windows Edition and attempts activation if it does not match the expected edition.
        /// Respects EnableActivation, RestartAfterActivation, and verbose logging settings.
        /// </summary>
        private async Task CheckWindowsEditionAndKmsAsync(CancellationToken stoppingToken)
        {
            string currentEdition = GetWindowsEdition();
            bool editionMatches = string.Equals(currentEdition, _expectedWindowsEdition, StringComparison.OrdinalIgnoreCase);

            if (_verboseLoggingLocal)
                _logger.LogInformation("Windows edition check: Current={CurrentEdition}, Expected={ExpectedEdition}, Match={Match}", currentEdition, _expectedWindowsEdition, editionMatches);

            if (_verboseLoggingAppInsight)
            {
                TrackTelemetryEvent(
                    "WindowsEditionCheck",
                    new Dictionary<string, string?>
                    {
                        ["CurrentEdition"] = currentEdition,
                        ["ExpectedEdition"] = _expectedWindowsEdition,
                        ["Match"] = editionMatches.ToString()
                    },
                    isInformational: true);
            }

            if (!editionMatches)
            {
                _logger.LogWarning("Windows edition mismatch: Current={CurrentEdition}, Expected={ExpectedEdition}", currentEdition, _expectedWindowsEdition);
                TrackTelemetryEvent(
                    "WindowsEditionMismatch",
                    new Dictionary<string, string?>

                    {
                        ["CurrentEdition"] = currentEdition,
                        ["ExpectedEdition"] = _expectedWindowsEdition
                    },
                    isInformational: false);

                if (_enableActivation && !string.IsNullOrWhiteSpace(_kmsKey))
                {
                    var activationResult = await TryActivateWindowsWithKmsKeyAsync(_kmsKey, stoppingToken);

                    if (_verboseLoggingLocal || !activationResult.Success)
                        _logger.LogInformation("Windows activation attempted. Success={Success}, Message={Message}", activationResult.Success, activationResult.Message);

                    TrackTelemetryEvent(
                        "WindowsActivationAttempt",
                        new Dictionary<string, string?>
                        {
                            ["Success"] = activationResult.Success.ToString(),
                            ["Message"] = activationResult.Message
                        },
                        isInformational: !activationResult.Success ? false : _verboseLoggingAppInsight);

                    if (activationResult.Success && _restartAfterActivation)
                    {
                        _logger.LogWarning("Restarting system after successful activation as per configuration.");
                        TrackTelemetryEvent(
                            "WindowsRestartAfterActivation",
                            new Dictionary<string, string?>(),
                            isInformational: false);

                        // Initiate restart
                        Process.Start(new ProcessStartInfo("shutdown", "/r /t 5")
                        {
                            CreateNoWindow = true,
                            UseShellExecute = false
                        });
                    }
                }
            }
        }

        /// <summary>
        /// Gets the current Windows Edition using WMI.
        /// </summary>
        private string GetWindowsEdition()
        {
            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT Caption FROM Win32_OperatingSystem");
                foreach (var os in searcher.Get())
                {
                    var caption = os["Caption"]?.ToString() ?? string.Empty;
                    // Example: "Microsoft Windows 10 Enterprise"
                    var parts = caption.Split(' ');
                    if (parts.Length >= 1)
                        return parts.Last(); // "Enterprise", "Pro", etc.
                    return caption;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get Windows edition.");
            }
            return string.Empty;
        }

        /// <summary>
        /// Attempts to activate Windows using the provided KMS key.
        /// </summary>
        private async Task<(bool Success, string Message)> TryActivateWindowsWithKmsKeyAsync(string kmsKey, CancellationToken stoppingToken)
        {
            try
            {
                // Set KMS key
                var setKey = await RunProcessAsync("cscript.exe", $"//Nologo slmgr.vbs /ipk {kmsKey}", stoppingToken);
                if (!setKey.Success)
                    return (false, $"Failed to set KMS key: {setKey.Message}");

                // Activate Windows
                var activate = await RunProcessAsync("cscript.exe", "//Nologo slmgr.vbs /ato", stoppingToken);
                if (!activate.Success)
                    return (false, $"Activation failed: {activate.Message}");

                return (true, "Activation succeeded.");
            }
            catch (Exception ex)
            {
                return (false, $"Exception during activation: {ex.Message}");
            }
        }

        /// <summary>
        /// Runs a process and returns the result.
        /// </summary>
        private async Task<(bool Success, string Message)> RunProcessAsync(string fileName, string arguments, CancellationToken stoppingToken)
        {
            try
            {
                using var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = fileName,
                        Arguments = arguments,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };
                process.Start();
                string output = await process.StandardOutput.ReadToEndAsync();
                string error = await process.StandardError.ReadToEndAsync();
                await process.WaitForExitAsync(stoppingToken);

                bool success = process.ExitCode == 0;
                string message = !string.IsNullOrWhiteSpace(error) ? error : output;
                return (success, message.Trim());
            }
            catch (Exception ex)
            {
                return (false, $"Process error: {ex.Message}");
            }
        }

        /// <summary>
        /// Gets the currently active user.
        /// </summary>
        private string GetActiveUser()
        {
            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_ComputerSystem");
                foreach (var obj in searcher.Get())
                {
                    var user = obj["UserName"]?.ToString();
                    if (!string.IsNullOrWhiteSpace(user))
                        return user;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get active user.");
            }
            return string.Empty;
        }

        /// <summary>
        /// Checks and logs the active user status.
        /// </summary>
        private void CheckAndLogActiveUser()
        {
            var activeUser = GetActiveUser();
            if (_kioskUsers == null || _kioskUsers.Count == 0)
            {
                if (_verboseLoggingLocal)
                    _logger.LogInformation("KioskUser list not configured. Skipping active user check.");
                return;
            }

            bool match = _kioskUsers.Any(u => string.Equals(activeUser, u, StringComparison.OrdinalIgnoreCase));
            if (match)
            {
                _logger.LogInformation("Kiosk user '{ActiveUser}' is currently active.", activeUser);
                TrackTelemetryEvent(
                    "KioskUserActive",
                    new Dictionary<string, string?>
                    {
                        ["ActiveUser"] = activeUser,
                        ["KioskUsers"] = string.Join(";", _kioskUsers)
                    },
                    isInformational: true);
            }
            else
            {
                _logger.LogWarning("Active user '{ActiveUser}' does not match any KioskUser.", activeUser);
                TrackTelemetryEvent(
                    "KioskUserMismatch",
                    new Dictionary<string, string?>
                    {
                        ["ActiveUser"] = activeUser,
                        ["KioskUsers"] = string.Join(";", _kioskUsers)
                    },
                    isInformational: false);
            }
        }

        /// <summary>
        /// Checks the default printer configuration and status.
        /// </summary>
        private void CheckDefaultPrinter()
        {
            if (string.IsNullOrWhiteSpace(_defaultPrinterName))
            {
                if (_verboseLoggingLocal)
                    _logger.LogWarning("DefaultPrinter name not configured.");
                TrackTelemetryEvent(
                    "DefaultPrinterConfigMissing",
                    new Dictionary<string, string?> { ["ConfiguredName"] = _defaultPrinterName },
                    isInformational: false);
                return;
            }

            string defaultPrinter = string.Empty;
            try
            {
                using (var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows NT\CurrentVersion\Windows"))
                {
                    defaultPrinter = key?.GetValue("Device")?.ToString() ?? "";
                    // Format: "Brother HL6300 series USB,winspool,Ne01:"
                    if (!string.IsNullOrWhiteSpace(defaultPrinter))
                    {
                        int commaIndex = defaultPrinter.IndexOf(',');
                        if (commaIndex > 0)
                            defaultPrinter = defaultPrinter.Substring(0, commaIndex);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get default printer.");
                TrackTelemetryEvent(
                    "DefaultPrinterReadError",
                    new Dictionary<string, string?> { ["Error"] = ex.Message },
                    isInformational: false);
                return;
            }

            // Find candidate printer (wildcard)
            string candidatePrinter = null;
            var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Printer");
            foreach (ManagementObject printer in searcher.Get())
            {
                var name = printer["Name"]?.ToString() ?? "";
                if (name.Contains(_defaultPrinterName, StringComparison.OrdinalIgnoreCase))
                {
                    candidatePrinter = name;
                    break; // Only first match
                }
            }

            bool match = !string.IsNullOrWhiteSpace(defaultPrinter) &&
                         candidatePrinter != null &&
                         string.Equals(defaultPrinter, candidatePrinter, StringComparison.OrdinalIgnoreCase);

            if (_defaultPrinterForceDefault && candidatePrinter != null && !match)
            {
                try
                {
                    var setDefaultProcess = new Process
                    {
                        StartInfo = new ProcessStartInfo
                        {
                            FileName = "RUNDLL32.EXE",
                            Arguments = $"PRINTUI.DLL,PrintUIEntry /y /n \"{candidatePrinter}\"",
                            CreateNoWindow = true,
                            UseShellExecute = false
                        }
                    };
                    setDefaultProcess.Start();
                    setDefaultProcess.WaitForExit(5000);

                    _logger.LogInformation("Default printer set to '{Printer}' by force.", candidatePrinter);
                    TrackTelemetryEvent(
                        "DefaultPrinterForced",
                        new Dictionary<string, string?>
                        {
                            ["Printer"] = candidatePrinter,
                            ["ConfiguredName"] = _defaultPrinterName
                        },
                        isInformational: false);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to set default printer '{Printer}'.", candidatePrinter);
                    TrackTelemetryEvent(
                        "DefaultPrinterForceError",
                        new Dictionary<string, string?>
                        {
                            ["Printer"] = candidatePrinter,
                            ["ConfiguredName"] = _defaultPrinterName,
                            ["Error"] = ex.Message
                        },
                        isInformational: false);
                }
            }
            else
            {
                if (match)
                {
                    if (_verboseLoggingLocal)
                        _logger.LogInformation("Default printer '{DefaultPrinter}' matches '{ConfiguredName}'.", defaultPrinter, _defaultPrinterName);
                    TrackTelemetryEvent(
                        "DefaultPrinterMatch",
                        new Dictionary<string, string?>
                        {
                            ["DefaultPrinter"] = defaultPrinter,
                            ["ConfiguredName"] = _defaultPrinterName
                        },
                        isInformational: true);
                }
                else
                {
                    _logger.LogWarning("Default printer '{DefaultPrinter}' does NOT match '{ConfiguredName}'.", defaultPrinter, _defaultPrinterName);
                    TrackTelemetryEvent(
                        "DefaultPrinterMismatch",
                        new Dictionary<string, string?>
                        {
                            ["DefaultPrinter"] = defaultPrinter,
                            ["ConfiguredName"] = _defaultPrinterName
                        },
                        isInformational: false);
                }
            }

            CheckDefaultPrinterOnline();
        }

        private void CheckDefaultPrinterOnline()
        {
            if (string.IsNullOrWhiteSpace(_defaultPrinterName))
                return;

            var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Printer");
            foreach (ManagementObject printer in searcher.Get())
            {
                var name = printer["Name"]?.ToString() ?? "";
                if (name.Contains(_defaultPrinterName, StringComparison.OrdinalIgnoreCase))
                {
                    // Use PrinterStatus for more reliable online/offline detection
                    int status = printer["PrinterStatus"] is int s ? s : 0;
                    // 3 = Ready, 4 = Offline, 5 = Paused, 1 = Other
                    bool isOnline = status == 3;

                    if (isOnline)
                    {
                        if (_verboseLoggingLocal)
                            _logger.LogInformation("Printer '{Printer}' is ONLINE (PrinterStatus={Status}).", name, status);
                        TrackTelemetryEvent(
                            "DefaultPrinterOnline",
                            new Dictionary<string, string?>
                            {
                                ["Printer"] = name,
                                ["ConfiguredName"] = _defaultPrinterName,
                                ["PrinterStatus"] = status.ToString()
                            },
                            isInformational: true);
                    }
                    else
                    {
                        _logger.LogWarning("Printer '{Printer}' is OFFLINE (PrinterStatus={Status}).", name, status);
                        TrackTelemetryEvent(
                            "DefaultPrinterOffline",
                            new Dictionary<string, string?>
                            {
                                ["Printer"] = name,
                                ["ConfiguredName"] = _defaultPrinterName,
                                ["PrinterStatus"] = status.ToString()
                            },
                            isInformational: false);
                    }
                    break;
                }
            }
        }

        /// <summary>
        /// Main execution loop for the background service.
        /// </summary>
        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            // Log Windows version and edition once at startup
            LogWindowsVersionAndEdition();

            // Log latest Windows updates at startup
            LogLatestWindowsUpdates();

            var crashReportTimer = 0;
            var licenseCheckTimer = _licenseCheckIntervalSeconds;
            var websiteCheckTimer = _websiteCheckIntervalSeconds;
            var processCheckTimer = _checkIntervalSeconds;
            var deviceCheckTimer = _deviceCheckIntervalSeconds;
            var portTestsCheckTimer = _portTestsCheckIntervalSeconds;
            var eventViewerCheckTimer = _eventViewerCheckIntervalSeconds;
            var cleanLocalLogTimer = 3600;
            var activeUserCheckTimer = 60;
            var kioskUserCheckTimer = _kioskUserCheckIntervalSeconds;
            var defaultPrinterCheckTimer = _defaultPrinterCheckIntervalSeconds;

            if (_defaultPrinterEnabled)
            {
                CheckDefaultPrinter();
            }

                while (!stoppingToken.IsCancellationRequested)
            {
                if (processCheckTimer <= 0 && _processMonitorEnabled)
                {
                    CheckProcessesAndSendTelemetry();
                    processCheckTimer = _checkIntervalSeconds;
                }

                if (crashReportTimer <= 0 && _crashReportMonitorEnabled)
                {
                    CheckAndMoveCrashReports();
                    crashReportTimer = _crashReportCheckIntervalSeconds;
                }

                if (licenseCheckTimer <= 0 && _windowsLicenseMonitorEnabled)
                {
                    await CheckWindowsEditionAndKmsAsync(stoppingToken);
                    licenseCheckTimer = _licenseCheckIntervalSeconds;
                }

                if (websiteCheckTimer <= 0 && _websiteMonitorEnabled)
                {
                    await CheckWebsitesConnectivityAsync();
                    websiteCheckTimer = _websiteCheckIntervalSeconds;
                }

                if (deviceCheckTimer <= 0 && _deviceMonitorEnabled)
                {
                    CheckDevicesAndSendTelemetry();
                    deviceCheckTimer = _deviceCheckIntervalSeconds;
                }

                if (portTestsCheckTimer <= 0 && _portTestsMonitorEnabled)
                {
                    CheckServerPortsAndSendTelemetry();
                    portTestsCheckTimer = _portTestsCheckIntervalSeconds;
                }

                if (eventViewerCheckTimer <= 0 && _eventViewerMonitorEnabled)
                {
                    CheckEventViewerForApplicationErrors();
                    eventViewerCheckTimer = _eventViewerCheckIntervalSeconds;
                }

                if (cleanLocalLogTimer <= 0 && _localLogEnabled)
                {
                    CleanLocalLogIfNeeded();
                    cleanLocalLogTimer = 3600;
                }

                if (activeUserCheckTimer <= 0 && _kioskUserEnabled)
                {
                    CheckAndLogActiveUser();
                    activeUserCheckTimer = 60;
                }

                if (kioskUserCheckTimer <= 0 && _kioskUserEnabled)
                {
                    CheckAndLogActiveUser();
                    kioskUserCheckTimer = _kioskUserCheckIntervalSeconds;
                }

                if (defaultPrinterCheckTimer <= 0 && _defaultPrinterEnabled)
                {
                    CheckDefaultPrinterOnline();
                    defaultPrinterCheckTimer = _defaultPrinterCheckIntervalSeconds;
                }

                await Task.Delay(System.TimeSpan.FromSeconds(1), stoppingToken);
                crashReportTimer--;
                licenseCheckTimer--;
                websiteCheckTimer--;
                processCheckTimer--;
                deviceCheckTimer--;
                portTestsCheckTimer--;
                eventViewerCheckTimer--;
                cleanLocalLogTimer--;
                activeUserCheckTimer--;
                kioskUserCheckTimer--;
                defaultPrinterCheckTimer--;
            }
        }

        /// <summary>
        /// Checks and logs the Windows version and edition at startup.
        /// </summary>
        private void LogWindowsVersionAndEdition()
        {
            string fullVersion = GetFullWindowsVersionString();

            // Local log
            _logger.LogInformation("{FullVersion}", fullVersion);

            // App Insights
            TrackTelemetryEvent(
                "WindowsStartupVersionEdition",
                new Dictionary<string, string?>
                {
                    ["FullVersion"] = fullVersion
                },
                isInformational: false);
        }

        /// <summary>
        /// Gets the current Windows version using WMI.
        /// </summary>
        private string GetWindowsVersion()
        {
            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT Version FROM Win32_OperatingSystem");
                foreach (var os in searcher.Get())
                {
                    return os["Version"]?.ToString() ?? string.Empty;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get Windows version.");
            }
            return string.Empty;
        }

        /// <summary>
        /// Gets the full Windows version string, e.g., "Windows 11 Enterprise 24H2".
        /// </summary>
        private string GetFullWindowsVersionString()
        {
            string caption = "";
            string edition = "";
            string displayVersion = "";

            // Get Caption (e.g., "Microsoft Windows 11 Enterprise")
            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT Caption FROM Win32_OperatingSystem");
                foreach (var os in searcher.Get())
                {
                    caption = os["Caption"]?.ToString() ?? "";
                    break;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get Windows caption.");
            }

            // Extract Edition (last word of caption)
            if (!string.IsNullOrWhiteSpace(caption))
            {
                var parts = caption.Split(' ');
                if (parts.Length >= 2)
                {
                    edition = parts.Last(); // "Enterprise", "Pro", etc.
                }
            }

            // Get DisplayVersion (e.g., "24H2") from registry
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
                displayVersion = key?.GetValue("DisplayVersion")?.ToString() ?? key?.GetValue("ReleaseId")?.ToString() ?? "";
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get Windows display version.");
            }

            // Compose string: "Windows 11 Enterprise 24H2"
            string result = caption;
            if (!string.IsNullOrWhiteSpace(displayVersion))
            {
                result += " " + displayVersion;
            }
            return result.Trim();
        }

        /// <summary>
        /// Gets the latest installed Windows updates (last 5), with robust date parsing.
        /// </summary>
        private List<(string KBArticle, string Title, string InstalledOn)> GetLatestInstalledUpdates()
        {
            var updates = new List<(string KBArticle, string Title, string InstalledOn)>();
            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT HotFixID, Description, InstalledOn FROM Win32_QuickFixEngineering");
                foreach (ManagementObject update in searcher.Get())
                {
                    string kb = update["HotFixID"]?.ToString() ?? "";
                    string title = update["Description"]?.ToString() ?? "";
                    string installedOnStr = update["InstalledOn"]?.ToString() ?? "";

                    // Try to parse date, fallback to raw string or "Unknown"
                    string installedOnDisplay = "Unknown";
                    if (!string.IsNullOrWhiteSpace(installedOnStr))
                    {
                        DateTime dt;
                        if (DateTime.TryParse(installedOnStr, out dt) && dt.Year > 2000)
                        {
                            installedOnDisplay = dt.ToString("yyyy-MM-dd");
                        }
                        else
                        {
                            installedOnDisplay = installedOnStr;
                        }
                    }

                    updates.Add((kb, title, installedOnDisplay));
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get installed updates.");
            }
            // Order by date descending if possible, else by KB
            return updates
                .OrderByDescending(u => u.InstalledOn)
                .Take(5)
                .ToList();
        }

        /// <summary>
        /// Checks the latest installed Windows updates and logs them to App Insights and an external file.
        /// </summary>
        private void LogLatestWindowsUpdates()
        {
            var updateLogPath = _configuration.GetValue<string>("UpdateLog:FilePath") ?? "windows-updates.log";
            var updates = GetLatestInstalledUpdates();

            // Format for logging
            string updateSummary = string.Join(Environment.NewLine, updates.Select(u =>
                $"KB: {u.KBArticle}, {u.Title}, Installed: {u.InstalledOn}"));

            // Local log file
            try
            {
                var logDir = Path.GetDirectoryName(updateLogPath);
                if (!string.IsNullOrWhiteSpace(logDir) && !Directory.Exists(logDir))
                    Directory.CreateDirectory(logDir);

                File.WriteAllText(updateLogPath, updateSummary);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to write update log file: {Path}", updateLogPath);
            }

            // ILogger
            _logger.LogInformation("Latest Windows updates:\n{UpdateSummary}", updateSummary);

            // App Insights
            TrackTelemetryEvent(
                "WindowsLatestUpdates",
                new Dictionary<string, string?>
                {
                    ["UpdateSummary"] = updateSummary
                },
                isInformational: false);
        }
    }
}
