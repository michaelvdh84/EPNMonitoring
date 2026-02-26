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
        /// Tests the secure channel to the domain controller.
        /// This is equivalent to PowerShell's Test-ComputerSecureChannel cmdlet.
        /// </summary>
        private async Task CheckSecureChannelAsync(CancellationToken stoppingToken)
        {
            try
            {
                if (_verboseLoggingLocal)
                    _logger.LogInformation("Starting secure channel test...");

                // Use nltest /sc_query to test the secure channel
                // This is the Windows native tool that Test-ComputerSecureChannel uses under the hood
                var result = await RunProcessAsync("nltest", "/sc_query:" + Environment.UserDomainName, stoppingToken);

                if (!result.Success)
                {
                    _logger.LogError("Secure channel test failed: {Message}", result.Message);
                    TrackTelemetryEvent(
                        "SecureChannelTestFailed",
                        new Dictionary<string, string?>
                        {
                            ["Domain"] = Environment.UserDomainName,
                            ["Error"] = result.Message
                        },
                        isInformational: false);
                    return;
                }

                // Parse the output to determine if the secure channel is healthy
                // nltest /sc_query returns information about the secure channel status
                // A successful status typically contains "NERR_Success" or "The command completed successfully"
                string output = result.Message;
                bool isHealthy = output.Contains("NERR_Success", StringComparison.OrdinalIgnoreCase) ||
                                output.Contains("successfully", StringComparison.OrdinalIgnoreCase);

                if (!isHealthy)
                {
                    _logger.LogError("Secure channel is not healthy. Domain: {Domain}, Output: {Output}", 
                        Environment.UserDomainName, output);

                    TrackTelemetryEvent(
                        "SecureChannelUnhealthy",
                        new Dictionary<string, string?>
                        {
                            ["Domain"] = Environment.UserDomainName,
                            ["Output"] = output
                        },
                        isInformational: false);
                }
                else
                {
                    if (_verboseLoggingLocal)
                        _logger.LogInformation("Secure channel is healthy. Domain: {Domain}", Environment.UserDomainName);

                    if (_verboseLoggingAppInsight)
                    {
                        TrackTelemetryEvent(
                            "SecureChannelHealthy",
                            new Dictionary<string, string?>
                            {
                                ["Domain"] = Environment.UserDomainName
                            },
                            isInformational: true);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Exception occurred while checking secure channel");
                TrackTelemetryEvent(
                    "SecureChannelCheckException",
                    new Dictionary<string, string?>
                    {
                        ["Domain"] = Environment.UserDomainName,
                        ["Exception"] = ex.Message
                    },
                    isInformational: false);
            }
        }
    }
}
