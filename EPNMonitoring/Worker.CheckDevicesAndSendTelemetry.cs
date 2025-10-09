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
        /// Checks if the specified devices are present and sends the result to Application Insights.
        /// </summary>
        private void CheckDevicesAndSendTelemetry()
        {
            var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_PnPEntity");
            var devices = searcher.Get().Cast<ManagementObject>()
                .Select(mo => mo["Name"]?.ToString() ?? string.Empty)
                .ToList();

            if (_verboseLoggingLocal)
            {
                _logger.LogInformation("Device check started. Configured devices to check: {Count}", _devicesToCheck.Count);
                _logger.LogInformation("Detected devices from Win32_PnPEntity: {DeviceList}", string.Join("; ", devices));
            }

            int foundCount = 0, missingCount = 0;

            foreach (var deviceName in _devicesToCheck)
            {
                bool found = devices.Any(d => d.Contains(deviceName, System.StringComparison.OrdinalIgnoreCase));
                if (!found)
                {
                    _logger.LogWarning("Device not found: {DeviceName}", deviceName);
                    missingCount++;
                    TrackTelemetryEvent(
                        "DeviceNotFound",
                        new Dictionary<string, string?> { ["DeviceName"] = deviceName },
                        isInformational: false);
                }
                else
                {
                    foundCount++;
                    if (_verboseLoggingLocal)
                        _logger.LogInformation("Device found: {DeviceName}", deviceName);
                }
            }

            if (_verboseLoggingLocal)
                _logger.LogInformation("Device check summary: {Found} found, {Missing} missing, {Total} total.", foundCount, missingCount, _devicesToCheck.Count);

            // Flushing handled by TrackTelemetryEvent
        }
    }
}
