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
        /// Enables Application Insights internal diagnostics logging.
        /// </summary>
        private void EnableApplicationInsightsDiagnostics()
        {
            try
            {
                var logFilePath = _configuration.GetValue<string>("LocalLog:FilePath") ?? "ai-internal.log";
                var logDir = Path.GetDirectoryName(logFilePath);
                if (!string.IsNullOrEmpty(logDir) && !Directory.Exists(logDir))
                {
                    Directory.CreateDirectory(logDir);
                }

                // Extra diagnostics: log file path and directory existence
                if (_verboseLoggingLocal)
                    _logger.LogInformation("Attempting to initialize local log file at: {LogFilePath}", logFilePath);
                if (!Directory.Exists(logDir))
                {
                    if (_verboseLoggingLocal)
                        _logger.LogWarning("Log directory does not exist after creation attempt: {LogDir}", logDir);
                }

                if (!System.Diagnostics.Trace.Listeners.OfType<TimestampedTextWriterTraceListener>()
                    .Any(l => l.Writer is StreamWriter sw && sw.BaseStream is FileStream fs && fs.Name == logFilePath))
                {
                    System.Diagnostics.Trace.Listeners.Add(new TimestampedTextWriterTraceListener(logFilePath));
                    System.Diagnostics.Trace.AutoFlush = true;
                    if (_verboseLoggingLocal)
                        _logger.LogInformation("Local log file listener added successfully: {LogFilePath}", logFilePath);
                }
                else
                {
                    if (_verboseLoggingLocal)
                        _logger.LogInformation("Local log file listener already exists for: {LogFilePath}", logFilePath);
                }

                // Test write to log file
                System.Diagnostics.Trace.WriteLine("Local log file initialized successfully.");
            }
            catch (Exception ex)
            {
                // Fallback: log to Windows Event Log if file cannot be created
                try
                {
                    EventLog.WriteEntry("EPNMonitoring", $"Failed to initialize local log file: {ex}", EventLogEntryType.Error);
                }
                catch
                {
                    // Swallow to avoid recursive errors
                }
                // Also log to ILogger for visibility
                _logger.LogError(ex, "Exception occurred while initializing local log file.");
            }
        }
    }
}
