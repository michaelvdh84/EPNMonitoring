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
        private void CheckDefaultPrinterOnline()
        {
            if (string.IsNullOrWhiteSpace(_defaultPrinterName))
                return;

            var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Printer");
            foreach (ManagementObject printer in searcher.Get())
            {
                var name = printer["Name"]?.ToString() ?? "";
                if (name.Contains(_defaultPrinterName, StringComparison.OrdinalIgnoreCase))
                {
                    // Use PrinterStatus for more reliable online/offline detection
                    int status = printer["PrinterStatus"] is int s ? s : 0;
                    // 3 = Ready, 4 = Offline, 5 = Paused, 1 = Other
                    bool isOnline = status == 3;

                    if (isOnline)
                    {
                        if (_verboseLoggingLocal)
                            _logger.LogInformation("Printer '{Printer}' is ONLINE (PrinterStatus={Status}).", name, status);
                        TrackTelemetryEvent(
                            "DefaultPrinterOnline",
                            new Dictionary<string, string?>
                            {
                                ["Printer"] = name,
                                ["ConfiguredName"] = _defaultPrinterName,
                                ["PrinterStatus"] = status.ToString()
                            },
                            isInformational: true);
                    }
                    else
                    {
                        _logger.LogWarning("Printer '{Printer}' is OFFLINE (PrinterStatus={Status}).", name, status);
                        TrackTelemetryEvent(
                            "DefaultPrinterOffline",
                            new Dictionary<string, string?>
                            {
                                ["Printer"] = name,
                                ["ConfiguredName"] = _defaultPrinterName,
                                ["PrinterStatus"] = status.ToString()
                            },
                            isInformational: false);
                    }
                    break;
                }
            }
        }
    }
}
