using Microsoft.ApplicationInsights;
using Microsoft.ApplicationInsights.DataContracts;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
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
    public partial class Worker : BackgroundService
    {
        private readonly ILogger<Worker> _logger;
        private readonly TelemetryClient _telemetryClient;
        private readonly IConfiguration _configuration;
        private readonly FileLoggerProvider _fileLoggerProvider;

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

        // Get AD Site settings
        private readonly bool _getAdSiteEnabled;
        private readonly string _expectedAdSite;

        // Test secure channel settings
        private readonly bool _testSecureChannelEnabled;
        private readonly int _testSecureChannelCheckIntervalSeconds;

        // Last computer password update settings
        private readonly bool _lastComputerPasswordUpdateEnabled;

        public Worker(
            ILogger<Worker> logger,
            TelemetryClient telemetryClient,
            IConfiguration configuration,
            FileLoggerProvider fileLoggerProvider = null)
        {
            _logger = logger;
            _telemetryClient = telemetryClient;
            _configuration = configuration;
            _fileLoggerProvider = fileLoggerProvider;

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

            // Get AD Site settings
            var getAdSiteSection = _configuration.GetSection("GetAdSite");
            _getAdSiteEnabled = getAdSiteSection.GetValue<bool>("Enabled", true);
            _expectedAdSite = getAdSiteSection.GetValue<string>("ExpectedADSite", "");

            // Test secure channel settings
            var testSecureChannelSection = _configuration.GetSection("TestSecureChannel");
            _testSecureChannelEnabled = testSecureChannelSection.GetValue<bool>("Enabled", true);
            _testSecureChannelCheckIntervalSeconds = testSecureChannelSection.GetValue<int>("CheckIntervalSeconds", 300);

            // Last computer password update settings
            var lastComputerPasswordUpdateSection = _configuration.GetSection("CheckLastComputerPasswordUpdate");
            _lastComputerPasswordUpdateEnabled = lastComputerPasswordUpdateSection.GetValue<bool>("Enabled", true);

            if (_lastComputerPasswordUpdateEnabled)
                _logger.LogInformation("Computer password update check is ENABLED by configuration.");
            else
                _logger.LogInformation("Computer password update check is DISABLED by configuration.");
        }
    }
}
