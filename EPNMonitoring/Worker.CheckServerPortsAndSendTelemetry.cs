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
    }
}
