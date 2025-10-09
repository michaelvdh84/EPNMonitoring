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
    }
}
