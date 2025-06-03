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
        private readonly string _kmsKey;
        private readonly int _websiteCheckIntervalSeconds;
        private readonly List<string> _websites;
        private readonly bool _verboseLoggingLocal;
        private readonly bool _verboseLoggingAppInsight;
        private readonly List<string> _devicesToCheck;
        private readonly int _deviceCheckIntervalSeconds;

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
            _kmsKey = _configuration.GetValue<string>("WindowsLicenseMonitor:KmsKey", null);

            // Website monitor config
            _websiteCheckIntervalSeconds = _configuration.GetValue<int>("WebsiteMonitor:CheckIntervalSeconds", 300);
            _websites = _configuration.GetSection("WebsiteMonitor:Sites").Get<List<string>>() ?? new List<string>();

            // Device monitor config
            _devicesToCheck = _configuration.GetSection("DeviceMonitor:Devices").Get<List<string>>() ?? new List<string>();
            _deviceCheckIntervalSeconds = _configuration.GetValue<int>("DeviceMonitor:CheckIntervalSeconds", 60);

            // Verbose logging config
            _verboseLoggingLocal = _configuration.GetValue<bool>("VerboseLogging:Local", false);
            _verboseLoggingAppInsight = _configuration.GetValue<bool>("VerboseLogging:AppInsight", false);

            // Enable Application Insights diagnostics
            EnableApplicationInsightsDiagnostics();
        }

        /// <summary>
        /// Enables Application Insights internal diagnostics logging to capture telemetry send errors.
        /// Errors will be logged using the provided ILogger and written to a file with timestamps.
        /// </summary>
        private void EnableApplicationInsightsDiagnostics()
        {
            var logFilePath = _configuration.GetValue<string>("LocalLog:FilePath") ?? "ai-internal.log";
            var logDir = Path.GetDirectoryName(logFilePath);
            if (!string.IsNullOrEmpty(logDir) && !Directory.Exists(logDir))
            {
                Directory.CreateDirectory(logDir);
            }
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
                var processName = exe.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
                    ? exe[..^4]
                    : exe;

                var isRunning = Process.GetProcessesByName(processName).Any();

                if (!isRunning)
                {
                    if (_verboseLoggingLocal)
                        _logger.LogInformation("Process '{ProcessName}' is NOT running: {IsRunning}", exe, isRunning);
                    _logger.LogWarning("Process '{ProcessName}' is NOT running!", exe);

                    if (_verboseLoggingAppInsight)
                    {
                        var telemetry = new EventTelemetry("ProcessNotRunning")
                        {
                            Timestamp = DateTimeOffset.Now
                        };
                        telemetry.Properties["ProcessName"] = exe;
                        telemetry.Properties["IsRunning"] = isRunning.ToString();
                        _telemetryClient.TrackEvent(telemetry);
                    }
                }
                else if (_verboseLoggingLocal)
                {
                    _logger.LogInformation("Process '{ProcessName}' is running.", exe);
                    if (_verboseLoggingAppInsight)
                    {
                        var telemetry = new EventTelemetry("ProcessRunning")
                        {
                            Timestamp = DateTimeOffset.Now
                        };
                        telemetry.Properties["ProcessName"] = exe;
                        telemetry.Properties["IsRunning"] = isRunning.ToString();
                        _telemetryClient.TrackEvent(telemetry);
                    }
                }
            }
            if (_verboseLoggingAppInsight)
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
                if (_verboseLoggingLocal)
                    _logger.LogWarning("Crash report folder does not exist: {FolderPath}", _crashReportFolder);
                return;
            }
            if (string.IsNullOrWhiteSpace(_crashReportDestinationFolder))
            {
                if (_verboseLoggingLocal)
                    _logger.LogWarning("Crash report destination folder is not set.");
                return;
            }
            if (!Directory.Exists(_crashReportDestinationFolder))
            {
                Directory.CreateDirectory(_crashReportDestinationFolder);
            }

            var files = Directory.GetFiles(_crashReportFolder);
            var crashGroups = files
                .Select(f => new FileInfo(f))
                .GroupBy(f => Path.GetFileNameWithoutExtension(f.Name));

            foreach (var group in crashGroups)
            {
                var firstFile = group.OrderBy(f => f.CreationTime).First();

                _logger.LogWarning("Crash report detected: {BaseName}, Created: {CreationTime}", group.Key, firstFile.CreationTime);

                if (_verboseLoggingAppInsight)
                {
                    var telemetry = new EventTelemetry("CrashReportDetected")
                    {
                        Timestamp = DateTimeOffset.Now
                    };
                    telemetry.Properties["BaseName"] = group.Key;
                    telemetry.Properties["CreationTime"] = firstFile.CreationTime.ToString("o");
                    _telemetryClient.TrackEvent(telemetry);
                }

                foreach (var file in group)
                {
                    var destPath = Path.Combine(_crashReportDestinationFolder, file.Name);
                    try
                    {
                        File.Move(file.FullName, destPath, overwrite: true);
                        if (_verboseLoggingLocal)
                            _logger.LogInformation("Crash report file moved to: {Destination}", destPath);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Failed to move crash report file: {FileName}", file.Name);
                    }
                }
            }

            if (files.Length > 0 && _verboseLoggingAppInsight)
            {
                _telemetryClient.Flush();
            }
        }

        /// <summary>
        /// Checks if the Windows edition matches the expected value, if the KMS server port is reachable,
        /// and if the DNS entry exists. Logs detailed errors locally and sends telemetry if any check fails.
        /// Verbose logging for local and Application Insights is controlled by appsettings.
        /// </summary>
        private void CheckWindowsEditionAndKms()
        {
            string edition = GetWindowsEdition();
            bool editionOk = edition.Equals(_expectedWindowsEdition, StringComparison.OrdinalIgnoreCase);

            // Verbose: log detected and expected edition
            if (_verboseLoggingLocal)
                _logger.LogInformation("Detected Windows edition: {Edition}, Expected: {ExpectedEdition}", edition, _expectedWindowsEdition);
            if (_verboseLoggingAppInsight)
            {
                var telemetry = new EventTelemetry("WindowsEditionCheckInfo")
                {
                    Timestamp = DateTimeOffset.Now
                };
                telemetry.Properties["DetectedEdition"] = edition;
                telemetry.Properties["ExpectedEdition"] = _expectedWindowsEdition;
                _telemetryClient.TrackEvent(telemetry);
            }

            bool kmsPortOk = true;
            string kmsPortError = null;

            string kmsPortInformation = null;
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
                        if (_verboseLoggingAppInsight)
                        {
                            var telemetry = new EventTelemetry("KmsPortCheckFailed")
                            {
                                Timestamp = DateTimeOffset.Now
                            };
                            telemetry.Properties["KmsServer"] = _kmsServer;
                            telemetry.Properties["KmsServerPort"] = _kmsServerPort.ToString();
                            telemetry.Properties["Error"] = kmsPortError;
                            _telemetryClient.TrackEvent(telemetry);
                        }
                    }
                    else if (_verboseLoggingLocal)
                    {
                        kmsPortInformation = $"KMS server '{_kmsServer}' port {_kmsServerPort} is reachable.";
                        _logger.LogInformation(kmsPortInformation);
                        if (_verboseLoggingAppInsight)
                        {
                            var telemetry = new EventTelemetry("KmsPortOpened")
                            {
                                Timestamp = DateTimeOffset.Now
                            };
                            telemetry.Properties["KmsServer"] = _kmsServer;
                            telemetry.Properties["KmsServerPort"] = _kmsServerPort.ToString();
                            telemetry.Properties["Information"] = kmsPortInformation;
                            _telemetryClient.TrackEvent(telemetry);
                        }
                    }
                }
                catch (Exception ex)
                {
                    kmsPortOk = false;
                    kmsPortError = $"KMS server '{_kmsServer}' port {_kmsServerPort} check failed: {ex.Message}";
                    _logger.LogError(kmsPortError);
                    if (_verboseLoggingAppInsight)
                    {
                        var telemetry = new EventTelemetry("KmsPortCheckException")
                        {
                            Timestamp = DateTimeOffset.Now
                        };
                        telemetry.Properties["KmsServer"] = _kmsServer;
                        telemetry.Properties["KmsServerPort"] = _kmsServerPort.ToString();
                        telemetry.Properties["Exception"] = ex.Message;
                        _telemetryClient.TrackEvent(telemetry);
                    }
                }
            }

            bool dnsOk = true;
            string dnsError = null;
            string dnsInformation = null;
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
                        if (_verboseLoggingAppInsight)
                        {
                            var telemetry = new EventTelemetry("KmsDnsCheckFailed")
                            {
                                Timestamp = DateTimeOffset.Now
                            };
                            telemetry.Properties["KmsDnsEntry"] = _kmsDnsEntry;
                            telemetry.Properties["Error"] = dnsError;
                            _telemetryClient.TrackEvent(telemetry);
                        }
                    }
                    else if (_verboseLoggingLocal)
                    {
                        dnsInformation = $"DNS entry ' _kmsDnsEntry' is present.";
                        _logger.LogInformation(dnsInformation);
                        if (_verboseLoggingAppInsight)
                        {
                            var telemetry = new EventTelemetry("KmsDnsSuccess")
                            {
                                Timestamp = DateTimeOffset.Now
                            };
                            telemetry.Properties["KmsDnsEntry"] = _kmsDnsEntry;
                            telemetry.Properties["Information"] = dnsInformation;
                            _telemetryClient.TrackEvent(telemetry);
                        }

                    }
                }
                catch (Exception ex)
                {
                    dnsOk = false;
                    dnsError = $"DNS entry '{_kmsDnsEntry}' check failed: {ex.Message}";
                    _logger.LogError(dnsError);
                    if (_verboseLoggingAppInsight)
                    {
                        var telemetry = new EventTelemetry("KmsDnsCheckException")
                        {
                            Timestamp = DateTimeOffset.Now
                        };
                        telemetry.Properties["KmsDnsEntry"] = _kmsDnsEntry;
                        telemetry.Properties["Exception"] = ex.Message;
                        _telemetryClient.TrackEvent(telemetry);
                    }
                }
            }

            if (!editionOk)
            {
                string editionError = $"Windows edition mismatch: Detected '{edition}', expected '{_expectedWindowsEdition}'.";
                _logger.LogError(editionError);
                if (_verboseLoggingAppInsight)
                {
                    var telemetry = new EventTelemetry("WindowsEditionMismatch")
                    {
                        Timestamp = DateTimeOffset.Now
                    };
                    telemetry.Properties["DetectedEdition"] = edition;
                    telemetry.Properties["ExpectedEdition"] = _expectedWindowsEdition;
                    _telemetryClient.TrackEvent(telemetry);
                }
            }

            // Only send telemetry if edition is not as expected, KMS port check fails, or DNS check fails
            if (!editionOk || !kmsPortOk || !dnsOk)
            {
                string message = $"Windows license check: Edition: {edition} (expected: {_expectedWindowsEdition}), " +
                                 $"KMS Port: {(kmsPortOk ? "OK" : kmsPortError)}, DNS: {(dnsOk ? "OK" : dnsError)}";
                _logger.LogWarning(message);

                if (_verboseLoggingAppInsight)
                {
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

            // Attempt to activate Windows if the edition is not as expected
            if (!editionOk)
            {
                TryActivateWindowsWithKmsKey(edition);
            }
        }

        /// <summary>
        /// Attempts to activate Windows using the provided KMS key via slmgr.vbs.
        /// Logs the output and result.
        /// </summary>
        private void TryActivateWindowsWithKmsKey(string detectedEdition)
        {
            if (string.IsNullOrWhiteSpace(_kmsKey))
            {
                _logger.LogWarning("No KMS key specified in configuration. Skipping activation attempt.");
                return;
            }

            string maskedKmsKey = _kmsKey.Length > 5
                ? new string('*', _kmsKey.Length - 5) + _kmsKey[^5..]
                : _kmsKey;

            // Send telemetry about the activation attempt
            if (_verboseLoggingAppInsight)
            {
                var telemetry = new EventTelemetry("WindowsActivationAttempt")
                {
                    Timestamp = DateTimeOffset.Now
                };
                telemetry.Properties["DetectedEdition"] = detectedEdition;
                telemetry.Properties["ExpectedEdition"] = _expectedWindowsEdition;
                telemetry.Properties["KmsKey"] = maskedKmsKey;
                telemetry.Properties["KmsServer"] = _kmsServer ?? "";
                telemetry.Properties["KmsServerPort"] = _kmsServerPort.ToString();

                _telemetryClient.TrackEvent(telemetry);
                _telemetryClient.Flush();
            }

            if (_verboseLoggingLocal)
                _logger.LogInformation("Attempting Windows activation with KMS key (masked): {KmsKey}", maskedKmsKey);

            try
            {
                var installKey = RunSlmgrCommand($"/ipk {_kmsKey}");
                if (_verboseLoggingLocal)
                    _logger.LogInformation("KMS key installation output: {Output}", installKey);

                if (!string.IsNullOrWhiteSpace(_kmsServer))
                {
                    var setServer = RunSlmgrCommand($"/skms {_kmsServer}:{_kmsServerPort}");
                    if (_verboseLoggingLocal)
                        _logger.LogInformation("KMS server set output: {Output}", setServer);
                }

                var activate = RunSlmgrCommand("/ato");
                if (_verboseLoggingLocal)
                    _logger.LogInformation("KMS activation output: {Output}", activate);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to activate Windows with KMS key.");
            }
        }

        /// <summary>
        /// Runs a slmgr.vbs command and returns the output.
        /// </summary>
        private string RunSlmgrCommand(string arguments)
        {
            var psi = new ProcessStartInfo
            {
                FileName = "cscript",
                Arguments = $"//Nologo %windir%\\system32\\slmgr.vbs {arguments}",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var process = Process.Start(psi);
            string output = process.StandardOutput.ReadToEnd();
            string error = process.StandardError.ReadToEnd();
            process.WaitForExit();

            if (!string.IsNullOrWhiteSpace(error))
                output += Environment.NewLine + error;

            return output;
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
        /// Checks connectivity to each website specified in the configuration.
        /// Logs locally and sends telemetry if a site is unreachable.
        /// </summary>
        private async Task CheckWebsitesConnectivityAsync()
        {
            foreach (var site in _websites)
            {
                try
                {
                    using var httpClient = new HttpClient();
                    httpClient.Timeout = TimeSpan.FromSeconds(5);
                    var response = await httpClient.GetAsync(site);
                    if (!response.IsSuccessStatusCode)
                    {
                        _logger.LogWarning("Website unreachable (HTTP {StatusCode}): {Site}", (int)response.StatusCode, site);
                        SendWebsiteUnreachableTelemetry(site, $"HTTP {(int)response.StatusCode}");
                    }
                    else if (_verboseLoggingLocal)
                    {
                        _logger.LogInformation("Website reachable: {Site}", site);
                        if (_verboseLoggingAppInsight)
                        {
                            var telemetry = new EventTelemetry("WebsiteReachable")
                            {
                                Timestamp = DateTimeOffset.Now
                            };
                            telemetry.Properties["Site"] = site;
                            telemetry.Properties["StatusCode"] = ((int)response.StatusCode).ToString();
                            _telemetryClient.TrackEvent(telemetry);
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Website unreachable: {Site}", site);
                    SendWebsiteUnreachableTelemetry(site, ex.Message);
                }
            }
            if (_verboseLoggingAppInsight)
                _telemetryClient.Flush();
        }

        /// <summary>
        /// Sends telemetry to Application Insights for unreachable websites.
        /// </summary>
        private void SendWebsiteUnreachableTelemetry(string site, string reason)
        {
            var telemetry = new EventTelemetry("WebsiteUnreachable")
            {
                Timestamp = DateTimeOffset.Now
            };
            telemetry.Properties["Site"] = site;
            telemetry.Properties["Reason"] = reason;
            _telemetryClient.TrackEvent(telemetry);
            _telemetryClient.Flush();
        }

        /// <summary>
        /// Checks if the specified devices are present and sends the result to Application Insights.
        /// </summary>
        private void CheckDevicesAndSendTelemetry()
        {
            var searcher = new System.Management.ManagementObjectSearcher("SELECT * FROM Win32_PnPEntity");
            var devices = searcher.Get().Cast<System.Management.ManagementObject>()
                .Select(mo => mo["Name"]?.ToString() ?? string.Empty)
                .ToList();

            if (_verboseLoggingLocal)
            {
                _logger.LogInformation("Device check started. Configured devices to check: {Count}", _devicesToCheck.Count);
                _logger.LogInformation("Detected devices from Win32_PnPEntity: {DeviceList}", string.Join("; ", devices));
            }

            int foundCount = 0;
            int missingCount = 0;

            foreach (var deviceName in _devicesToCheck)
            {
                bool found = devices.Any(d => d.Contains(deviceName, StringComparison.OrdinalIgnoreCase));
                if (!found)
                {
                    _logger.LogWarning("Device not found: {DeviceName}", deviceName);
                    missingCount++;
                    if (_verboseLoggingAppInsight)
                    {
                        var telemetry = new EventTelemetry("DeviceNotFound")
                        {
                            Timestamp = DateTimeOffset.Now
                        };
                        telemetry.Properties["DeviceName"] = deviceName;
                        _telemetryClient.TrackEvent(telemetry);
                    }
                }
                else
                {
                    foundCount++;
                    if (_verboseLoggingLocal)
                    {
                        _logger.LogInformation("Device found: {DeviceName}", deviceName);
                    }
                }
            }

            if (_verboseLoggingLocal)
            {
                _logger.LogInformation("Device check summary: {Found} found, {Missing} missing, {Total} total.", foundCount, missingCount, _devicesToCheck.Count);
            }

            if (_verboseLoggingAppInsight)
                _telemetryClient.Flush();
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
            var websiteCheckTimer = _websiteCheckIntervalSeconds;
            var processCheckTimer = _checkIntervalSeconds;
            var deviceCheckTimer = _deviceCheckIntervalSeconds;

            while (!stoppingToken.IsCancellationRequested)
            {
                // Process monitor check
                if (processCheckTimer <= 0)
                {
                    CheckProcessesAndSendTelemetry();
                    processCheckTimer = _checkIntervalSeconds;
                }

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

                // Website connectivity check based on its own interval
                if (websiteCheckTimer <= 0)
                {
                    await CheckWebsitesConnectivityAsync();
                    websiteCheckTimer = _websiteCheckIntervalSeconds;
                }

                // Device check based on its own interval
                if (deviceCheckTimer <= 0)
                {
                    CheckDevicesAndSendTelemetry();
                    deviceCheckTimer = _deviceCheckIntervalSeconds;
                }


                await Task.Delay(TimeSpan.FromSeconds(1), stoppingToken);
                crashReportTimer--;
                licenseCheckTimer--;
                websiteCheckTimer--;
                processCheckTimer--;
                deviceCheckTimer--;
            }
        }
    }
}
