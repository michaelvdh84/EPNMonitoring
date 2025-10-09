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
        /// Checks the latest installed Windows updates and logs them to App Insights and an external file.
        /// </summary>
        private void LogLatestWindowsUpdates()
        {
            var updateLogPath = _configuration.GetValue<string>("UpdateLog:FilePath") ?? "windows-updates.log";
            var updates = GetLatestInstalledUpdates();

            // Format for logging
            string updateSummary = string.Join(Environment.NewLine, updates.Select(u =>
                $"KB: {u.KBArticle}, {u.Title}, Installed: {u.InstalledOn}"));

            // Local log file
            try
            {
                var logDir = Path.GetDirectoryName(updateLogPath);
                if (!string.IsNullOrWhiteSpace(logDir) && !Directory.Exists(logDir))
                    Directory.CreateDirectory(logDir);

                File.WriteAllText(updateLogPath, updateSummary);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to write update log file: {Path}", updateLogPath);
            }

            // ILogger
            _logger.LogInformation("Latest Windows updates:\n{UpdateSummary}", updateSummary);

            // App Insights
            TrackTelemetryEvent(
                "WindowsLatestUpdates",
                new Dictionary<string, string?>
                {
                    ["UpdateSummary"] = updateSummary
                },
                isInformational: false);
        }
    }
}
