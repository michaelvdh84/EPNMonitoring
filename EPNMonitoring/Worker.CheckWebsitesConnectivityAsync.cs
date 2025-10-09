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
    }
}
