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
    }
}
