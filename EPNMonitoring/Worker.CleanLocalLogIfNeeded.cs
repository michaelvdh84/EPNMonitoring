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
        private void CleanLocalLogIfNeeded()
        {
            var logSection = _configuration.GetSection("LocalLog");
            string logPath = logSection.GetValue<string>("FilePath");
            long maxSize = logSection.GetValue<long>("MaxLogSize", 10485760); // Default 10 MB
            bool autoclean = logSection.GetValue<bool>("Autoclean", false);

            if (string.IsNullOrWhiteSpace(logPath) || !File.Exists(logPath) || !autoclean)
                return;

            var fileInfo = new FileInfo(logPath);
            if (fileInfo.Length > maxSize)
            {
                try
                {
                    File.WriteAllText(logPath, string.Empty);
                    _logger.LogWarning("Local log file exceeded {MaxLogSize} bytes and was cleaned.", maxSize);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to clean local log file: {LogPath}", logPath);
                }
            }
        }
    }
}
