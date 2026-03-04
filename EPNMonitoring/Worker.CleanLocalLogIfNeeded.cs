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
using System.Text.RegularExpressions;
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

            if (string.IsNullOrWhiteSpace(logPath) || !autoclean)
                return;

            try
            {
                CleanTempLogFiles(logPath);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to clean temporary log files.");
            }

            if (!File.Exists(logPath))
                return;

            var fileInfo = new FileInfo(logPath);
            if (fileInfo.Length > maxSize)
            {
                try
                {
                    if (_fileLoggerProvider != null)
                    {
                        _fileLoggerProvider.TruncateLog();
                        _logger.LogWarning("Local log file exceeded {MaxLogSize} bytes and was rotated (keeping 5 backups).", maxSize);
                    }
                    else
                    {
                        File.WriteAllText(logPath, string.Empty);
                        _logger.LogWarning("Local log file exceeded {MaxLogSize} bytes and was cleaned (fallback method).", maxSize);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to clean local log file: {LogPath}", logPath);
                }
            }
        }

        private void CleanTempLogFiles(string logPath)
        {
            var logDirectory = Path.GetDirectoryName(logPath);
            var logFileName = Path.GetFileName(logPath);

            if (string.IsNullOrWhiteSpace(logDirectory) || !Directory.Exists(logDirectory))
                return;

            var guidPattern = new Regex(
                @"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}" + Regex.Escape(logFileName) + "$",
                RegexOptions.IgnoreCase);

            var tempFiles = Directory.GetFiles(logDirectory, $"*{logFileName}")
                .Where(f => guidPattern.IsMatch(Path.GetFileName(f)))
                .ToList();

            foreach (var tempFile in tempFiles)
            {
                try
                {
                    File.Delete(tempFile);
                    _logger.LogInformation("Deleted temporary log file: {TempFile}", tempFile);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to delete temporary log file: {TempFile}", tempFile);
                }
            }
        }
    }
}
