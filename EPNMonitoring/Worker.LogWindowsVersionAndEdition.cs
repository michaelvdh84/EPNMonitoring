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
    }
}
