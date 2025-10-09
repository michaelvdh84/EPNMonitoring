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
        /// Checks for crash reports in the configured folder, moves them if found, and logs/sends a single telemetry event per crash.
        /// </summary>
        private void CheckAndMoveCrashReports()
        {
            if (string.IsNullOrWhiteSpace(_crashReportFolder) || !Directory.Exists(_crashReportFolder))
            {
                if (_verboseLoggingLocal)
                    _logger.LogWarning("Crash report folder does not exist: {FolderPath}", _crashReportFolder);

                TrackTelemetryEvent(
                    "CrashReportFolderMissing",
                    new Dictionary<string, string?> { ["FolderPath"] = _crashReportFolder },
                    isInformational: false);
                return;
            }
            if (string.IsNullOrWhiteSpace(_crashReportDestinationFolder))
            {
                if (_verboseLoggingLocal)
                    _logger.LogWarning("Crash report destination folder is not set.");

                TrackTelemetryEvent(
                    "CrashReportDestinationMissing",
                    new Dictionary<string, string?>(),
                    isInformational: false);
                return;
            }
            if (!Directory.Exists(_crashReportDestinationFolder))
                Directory.CreateDirectory(_crashReportDestinationFolder);

            var files = Directory.GetFiles(_crashReportFolder);
            var crashGroups = files
                .Select(f => new FileInfo(f))
                .GroupBy(f => Path.GetFileNameWithoutExtension(f.Name));

            foreach (var group in crashGroups)
            {
                var firstFile = group.OrderBy(f => f.CreationTime).First();

                _logger.LogWarning("Crash report detected: {BaseName}, Created: {CreationTime}", group.Key, firstFile.CreationTime);

                TrackTelemetryEvent(
                    "CrashReportDetected",
                    new Dictionary<string, string?>
                    {
                        ["BaseName"] = group.Key,
                        ["CreationTime"] = firstFile.CreationTime.ToString("o")
                    },
                    isInformational: false);

                foreach (var file in group)
                {
                    var destPath = Path.Combine(_crashReportDestinationFolder, file.Name);
                    try
                    {
                        File.Move(file.FullName, destPath, overwrite: true);
                        if (_verboseLoggingLocal)
                            _logger.LogInformation("Crash report file moved to: {Destination}", destPath);
                    }
                    catch (System.Exception ex)
                    {
                        _logger.LogError(ex, "Failed to move crash report file: {FileName}", file.Name);
                    }
                }
            }

            // Flushing handled by TrackTelemetryEvent
        }
    }
}
