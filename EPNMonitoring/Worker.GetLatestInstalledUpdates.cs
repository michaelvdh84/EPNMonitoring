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
        /// Gets the latest installed Windows updates (last 5), with robust date parsing.
        /// </summary>
        private List<(string KBArticle, string Title, string InstalledOn)> GetLatestInstalledUpdates()
        {
            var updates = new List<(string KBArticle, string Title, string InstalledOn)>();
            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT HotFixID, Description, InstalledOn FROM Win32_QuickFixEngineering");
                foreach (ManagementObject update in searcher.Get())
                {
                    string kb = update["HotFixID"]?.ToString() ?? "";
                    string title = update["Description"]?.ToString() ?? "";
                    string installedOnStr = update["InstalledOn"]?.ToString() ?? "";

                    // Try to parse date, fallback to raw string or "Unknown"
                    string installedOnDisplay = "Unknown";
                    if (!string.IsNullOrWhiteSpace(installedOnStr))
                    {
                        DateTime dt;
                        if (DateTime.TryParse(installedOnStr, out dt) && dt.Year > 2000)
                        {
                            installedOnDisplay = dt.ToString("yyyy-MM-dd");
                        }
                        else
                        {
                            installedOnDisplay = installedOnStr;
                        }
                    }

                    updates.Add((kb, title, installedOnDisplay));
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get installed updates.");
            }
            // Order by date descending if possible, else by KB
            return updates
                .OrderByDescending(u => u.InstalledOn)
                .Take(5)
                .ToList();
        }
    }
}
