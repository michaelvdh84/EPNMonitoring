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
        /// Gets the Active Directory site using nltest command and logs it.
        /// Sends an error if the AD site does not match the expected value.
        /// </summary>
        private async Task GetAdSiteAsync(CancellationToken stoppingToken)
        {
            try
            {
                var result = await RunProcessAsync("nltest", "/dsgetsite", stoppingToken);
                
                if (!result.Success)
                {
                    _logger.LogError("Failed to retrieve AD Site: {Message}", result.Message);
                    TrackTelemetryEvent(
                        "ADSiteRetrievalFailed",
                        new Dictionary<string, string?>
                        {
                            ["Error"] = result.Message
                        },
                        isInformational: false);
                    return;
                }

                // Parse the AD site from the output
                // nltest /dsgetsite typically returns the site name on the first line or after a specific text
                string adSite = result.Message.Trim().Split('\n').FirstOrDefault()?.Trim() ?? string.Empty;
                
                // Log the current AD site
                if (_verboseLoggingLocal)
                    _logger.LogInformation("Active Directory Site: {ADSite}", adSite);

                // Always log to App Insights
                TrackTelemetryEvent(
                    "ADSiteStartup",
                    new Dictionary<string, string?>
                    {
                        ["ADSite"] = adSite,
                        ["ExpectedADSite"] = _expectedAdSite
                    },
                    isInformational: false);

                // Check if the AD site matches the expected value
                if (!string.IsNullOrWhiteSpace(_expectedAdSite) && 
                    !string.Equals(adSite, _expectedAdSite, StringComparison.OrdinalIgnoreCase))
                {
                    _logger.LogError("AD Site mismatch: Current={CurrentADSite}, Expected={ExpectedADSite}", 
                        adSite, _expectedAdSite);
                    
                    TrackTelemetryEvent(
                        "ADSiteMismatch",
                        new Dictionary<string, string?>
                        {
                            ["CurrentADSite"] = adSite,
                            ["ExpectedADSite"] = _expectedAdSite
                        },
                        isInformational: false);
                }
                else
                {
                    if (_verboseLoggingLocal)
                        _logger.LogInformation("AD Site matches expected value: {ADSite}", adSite);

                    if (_verboseLoggingAppInsight)
                    {
                        TrackTelemetryEvent(
                            "ADSiteMatch",
                            new Dictionary<string, string?>
                            {
                                ["ADSite"] = adSite
                            },
                            isInformational: true);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Exception occurred while checking AD Site");
                TrackTelemetryEvent(
                    "ADSiteCheckException",
                    new Dictionary<string, string?>
                    {
                        ["Exception"] = ex.Message,
                        ["StackTrace"] = ex.StackTrace
                    },
                    isInformational: false);
            }
        }
    }
}
