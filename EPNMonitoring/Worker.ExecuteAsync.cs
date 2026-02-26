using Microsoft.ApplicationInsights;
using Microsoft.ApplicationInsights.DataContracts;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace EPNMonitoring
{
    public partial class Worker
    {
        /// <summary>
        /// Main execution loop for the background service.
        /// </summary>
        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            // Log Windows version and edition once at startup
            LogWindowsVersionAndEdition();

            // Log latest Windows updates at startup
            LogLatestWindowsUpdates();

            // Get and log AD Site at startup
            if (_getAdSiteEnabled)
            {
                await GetAdSiteAsync(stoppingToken);
            }

            // Check last computer password update at startup
            if (_lastComputerPasswordUpdateEnabled)
            {
                try
                {
                    CheckLastComputerPasswordUpdate();
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to check last computer password update at startup");
                }
            }

            var crashReportTimer = 0;
            var licenseCheckTimer = _licenseCheckIntervalSeconds;
            var websiteCheckTimer = _websiteCheckIntervalSeconds;
            var processCheckTimer = _checkIntervalSeconds;
            var deviceCheckTimer = _deviceCheckIntervalSeconds;
            var portTestsCheckTimer = _portTestsCheckIntervalSeconds;
            var eventViewerCheckTimer = _eventViewerCheckIntervalSeconds;
            var cleanLocalLogTimer = _configuration.GetValue<int>("LocalLog:CheckIntervalSeconds", 60);
            var activeUserCheckTimer = 60;
            var kioskUserCheckTimer = _kioskUserCheckIntervalSeconds;
            var defaultPrinterCheckTimer = _defaultPrinterCheckIntervalSeconds;
            var testSecureChannelTimer = _testSecureChannelCheckIntervalSeconds;

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
                    cleanLocalLogTimer = _configuration.GetValue<int>("LocalLog:CheckIntervalSeconds", 60);
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

                if (testSecureChannelTimer <= 0 && _testSecureChannelEnabled)
                {
                    await CheckSecureChannelAsync(stoppingToken);
                    testSecureChannelTimer = _testSecureChannelCheckIntervalSeconds;
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
                testSecureChannelTimer--;
            }
        }
    }
}
