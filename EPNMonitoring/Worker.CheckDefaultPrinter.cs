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
        /// Checks the default printer configuration and status.
        /// </summary>
        private void CheckDefaultPrinter()
        {
            if (string.IsNullOrWhiteSpace(_defaultPrinterName))
            {
                if (_verboseLoggingLocal)
                    _logger.LogWarning("DefaultPrinter name not configured.");
                TrackTelemetryEvent(
                    "DefaultPrinterConfigMissing",
                    new Dictionary<string, string?> { ["ConfiguredName"] = _defaultPrinterName },
                    isInformational: false);
                return;
            }

            string defaultPrinter = string.Empty;
            try
            {
                using (var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows NT\CurrentVersion\Windows"))
                {
                    defaultPrinter = key?.GetValue("Device")?.ToString() ?? "";
                    // Format: "Brother HL6300 series USB,winspool,Ne01:"
                    if (!string.IsNullOrWhiteSpace(defaultPrinter))
                    {
                        int commaIndex = defaultPrinter.IndexOf(',');
                        if (commaIndex > 0)
                            defaultPrinter = defaultPrinter.Substring(0, commaIndex);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get default printer.");
                TrackTelemetryEvent(
                    "DefaultPrinterReadError",
                    new Dictionary<string, string?> { ["Error"] = ex.Message },
                    isInformational: false);
                return;
            }

            // Find candidate printer (wildcard)
            string candidatePrinter = null;
            var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Printer");
            foreach (ManagementObject printer in searcher.Get())
            {
                var name = printer["Name"]?.ToString() ?? "";
                if (name.Contains(_defaultPrinterName, StringComparison.OrdinalIgnoreCase))
                {
                    candidatePrinter = name;
                    break; // Only first match
                }
            }

            bool match = !string.IsNullOrWhiteSpace(defaultPrinter) &&
                         candidatePrinter != null &&
                         string.Equals(defaultPrinter, candidatePrinter, StringComparison.OrdinalIgnoreCase);

            if (_defaultPrinterForceDefault && candidatePrinter != null && !match)
            {
                try
                {
                    var setDefaultProcess = new Process
                    {
                        StartInfo = new ProcessStartInfo
                        {
                            FileName = "RUNDLL32.EXE",
                            Arguments = $"PRINTUI.DLL,PrintUIEntry /y /n \"{candidatePrinter}\"",
                            CreateNoWindow = true,
                            UseShellExecute = false
                        }
                    };
                    setDefaultProcess.Start();
                    setDefaultProcess.WaitForExit(5000);

                    _logger.LogInformation("Default printer set to '{Printer}' by force.", candidatePrinter);
                    TrackTelemetryEvent(
                        "DefaultPrinterForced",
                        new Dictionary<string, string?>
                        {
                            ["Printer"] = candidatePrinter,
                            ["ConfiguredName"] = _defaultPrinterName
                        },
                        isInformational: false);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to set default printer '{Printer}'.", candidatePrinter);
                    TrackTelemetryEvent(
                        "DefaultPrinterForceError",
                        new Dictionary<string, string?>
                        {
                            ["Printer"] = candidatePrinter,
                            ["ConfiguredName"] = _defaultPrinterName,
                            ["Error"] = ex.Message
                        },
                        isInformational: false);
                }
            }
            else
            {
                if (match)
                {
                    if (_verboseLoggingLocal)
                        _logger.LogInformation("Default printer '{DefaultPrinter}' matches '{ConfiguredName}'.", defaultPrinter, _defaultPrinterName);
                    TrackTelemetryEvent(
                        "DefaultPrinterMatch",
                        new Dictionary<string, string?>
                        {
                            ["DefaultPrinter"] = defaultPrinter,
                            ["ConfiguredName"] = _defaultPrinterName
                        },
                        isInformational: true);
                }
                else
                {
                    _logger.LogWarning("Default printer '{DefaultPrinter}' does NOT match '{ConfiguredName}'.", defaultPrinter, _defaultPrinterName);
                    TrackTelemetryEvent(
                        "DefaultPrinterMismatch",
                        new Dictionary<string, string?>
                        {
                            ["DefaultPrinter"] = defaultPrinter,
                            ["ConfiguredName"] = _defaultPrinterName
                        },
                        isInformational: false);
                }
            }

            CheckDefaultPrinterOnline();
        }
    }
}
