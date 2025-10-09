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
        /// Gets the full Windows version string, e.g., "Windows 11 Enterprise 24H2".
        /// </summary>
        private string GetFullWindowsVersionString()
        {
            string caption = "";
            string edition = "";
            string displayVersion = "";

            // Get Caption (e.g., "Microsoft Windows 11 Enterprise")
            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT Caption FROM Win32_OperatingSystem");
                foreach (var os in searcher.Get())
                {
                    caption = os["Caption"]?.ToString() ?? "";
                    break;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get Windows caption.");
            }

            // Extract Edition (last word of caption)
            if (!string.IsNullOrWhiteSpace(caption))
            {
                var parts = caption.Split(' ');
                if (parts.Length >= 2)
                {
                    edition = parts.Last(); // "Enterprise", "Pro", etc.
                }
            }

            // Get DisplayVersion (e.g., "24H2") from registry
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
                displayVersion = key?.GetValue("DisplayVersion")?.ToString() ?? key?.GetValue("ReleaseId")?.ToString() ?? "";
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get Windows display version.");
            }

            // Compose string: "Windows 11 Enterprise 24H2"
            string result = caption;
            if (!string.IsNullOrWhiteSpace(displayVersion))
            {
                result += " " + displayVersion;
            }
            return result.Trim();
        }
    }
}
