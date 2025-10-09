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
        /// Checks the current Windows Edition and attempts activation if it does not match the expected edition.
        /// Respects EnableActivation, RestartAfterActivation, and verbose logging settings.
        /// </summary>
        private async Task CheckWindowsEditionAndKmsAsync(CancellationToken stoppingToken)
        {
            string currentEdition = GetWindowsEdition();
            bool editionMatches = string.Equals(currentEdition, _expectedWindowsEdition, StringComparison.OrdinalIgnoreCase);

            if (_verboseLoggingLocal)
                _logger.LogInformation("Windows edition check: Current={CurrentEdition}, Expected={ExpectedEdition}, Match={Match}", currentEdition, _expectedWindowsEdition, editionMatches);

            if (_verboseLoggingAppInsight)
            {
                TrackTelemetryEvent(
                    "WindowsEditionCheck",
                    new Dictionary<string, string?>
                    {
                        ["CurrentEdition"] = currentEdition,
                        ["ExpectedEdition"] = _expectedWindowsEdition,
                        ["Match"] = editionMatches.ToString()
                    },
                    isInformational: true);
            }

            if (!editionMatches)
            {
                _logger.LogWarning("Windows edition mismatch: Current={CurrentEdition}, Expected={ExpectedEdition}", currentEdition, _expectedWindowsEdition);
                TrackTelemetryEvent(
                    "WindowsEditionMismatch",
                    new Dictionary<string, string?>

                    {
                        ["CurrentEdition"] = currentEdition,
                        ["ExpectedEdition"] = _expectedWindowsEdition
                    },
                    isInformational: false);

                if (_enableActivation && !string.IsNullOrWhiteSpace(_kmsKey))
                {
                    var activationResult = await TryActivateWindowsWithKmsKeyAsync(_kmsKey, stoppingToken);

                    if (_verboseLoggingLocal || !activationResult.Success)
                        _logger.LogInformation("Windows activation attempted. Success={Success}, Message={Message}", activationResult.Success, activationResult.Message);

                    TrackTelemetryEvent(
                        "WindowsActivationAttempt",
                        new Dictionary<string, string?>
                        {
                            ["Success"] = activationResult.Success.ToString(),
                            ["Message"] = activationResult.Message
                        },
                        isInformational: !activationResult.Success ? false : _verboseLoggingAppInsight);

                    if (activationResult.Success && _restartAfterActivation)
                    {
                        _logger.LogWarning("Restarting system after successful activation as per configuration.");
                        TrackTelemetryEvent(
                            "WindowsRestartAfterActivation",
                            new Dictionary<string, string?>(),
                            isInformational: false);

                        // Initiate restart
                        Process.Start(new ProcessStartInfo("shutdown", "/r /t 5")
                        {
                            CreateNoWindow = true,
                            UseShellExecute = false
                        });
                    }
                }
            }
        }
    }
}
