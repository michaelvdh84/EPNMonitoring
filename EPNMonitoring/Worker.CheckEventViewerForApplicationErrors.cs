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
    }
}
