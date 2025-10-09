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
    }
}
