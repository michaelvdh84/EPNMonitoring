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
        /// Gets the current Windows version using WMI.
        /// </summary>
        private string GetWindowsVersion()
        {
            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT Version FROM Win32_OperatingSystem");
                foreach (var os in searcher.Get())
                {
                    return os["Version"]?.ToString() ?? string.Empty;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get Windows version.");
            }
            return string.Empty;
        }
    }
}
