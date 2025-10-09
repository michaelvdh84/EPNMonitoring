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
        /// Gets the current Windows Edition using WMI.
        /// </summary>
        private string GetWindowsEdition()
        {
            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT Caption FROM Win32_OperatingSystem");
                foreach (var os in searcher.Get())
                {
                    var caption = os["Caption"]?.ToString() ?? string.Empty;
                    // Example: "Microsoft Windows 10 Enterprise"
                    var parts = caption.Split(' ');
                    if (parts.Length >= 1)
                        return parts.Last(); // "Enterprise", "Pro", etc.
                    return caption;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get Windows edition.");
            }
            return string.Empty;
        }
    }
}
