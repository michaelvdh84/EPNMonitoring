using Microsoft.ApplicationInsights;
using Microsoft.ApplicationInsights.DataContracts;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace EPNMonitoring
{
    public partial class Worker
    {
        /// <summary>
        /// Checks the last computer password update from the SECURITY registry hive.
        /// This method reads the $MACHINE.ACC\CupdTime key (requires SYSTEM privileges).
        /// </summary>
        private void CheckLastComputerPasswordUpdate()
        {
            try
            {
                _logger.LogInformation("Checking last computer password update from SECURITY hive...");

                var key = Registry.LocalMachine.OpenSubKey(
                    @"SECURITY\Policy\Secrets\$MACHINE.ACC\CupdTime", false);

                if (key == null)
                {
                    string errorMessage = "Registry key not found (may require SYSTEM privileges)";
                    _logger.LogError("Failed to retrieve computer password update: {Message}", errorMessage);
                    
                    TrackTelemetryEvent(
                        "ComputerPasswordUpdateCheckFailed",
                        new Dictionary<string, string?>
                        {
                            ["Error"] = errorMessage,
                            ["Reason"] = "Key not found - may not be running as SYSTEM"
                        },
                        isInformational: false);
                    return;
                }

                byte[]? rawBytes = key.GetValue("") as byte[];
                if (rawBytes == null || rawBytes.Length == 0)
                {
                    rawBytes = key.GetValue("CupdTime") as byte[];
                }
                key.Close();

                if (rawBytes != null && rawBytes.Length >= 8)
                {
                    long fileTime = BitConverter.ToInt64(rawBytes, 0);
                    
                    if (fileTime > 0)
                    {
                        DateTime utcTime = DateTime.FromFileTimeUtc(fileTime);
                        TimeZoneInfo brusselsTz = TimeZoneInfo.FindSystemTimeZoneById("Romance Standard Time");
                        DateTime brusselsTime = TimeZoneInfo.ConvertTimeFromUtc(utcTime, brusselsTz);
                        
                        string formattedBrusselsTime = brusselsTime.ToString("yyyy-MM-dd HH:mm:ss") + " (Brussels)";
                        string formattedUtcTime = utcTime.ToString("yyyy-MM-dd HH:mm:ss") + " (UTC)";
                        
                        TimeSpan timeSinceUpdate = DateTime.UtcNow - utcTime;
                        int daysSinceUpdate = (int)timeSinceUpdate.TotalDays;

                        _logger.LogInformation(
                            "Computer password last updated: {BrusselsTime} | {UtcTime} | {DaysSinceUpdate} days ago",
                            formattedBrusselsTime, formattedUtcTime, daysSinceUpdate);

                        TrackTelemetryEvent(
                            "ComputerPasswordUpdateCheck",
                            new Dictionary<string, string?>
                            {
                                ["LastUpdateUTC"] = utcTime.ToString("yyyy-MM-dd HH:mm:ss"),
                                ["LastUpdateBrussels"] = brusselsTime.ToString("yyyy-MM-dd HH:mm:ss"),
                                ["DaysSinceUpdate"] = daysSinceUpdate.ToString(),
                                ["Source"] = "SECURITY hive – CupdTime",
                                ["Detail"] = "Last machine account password update (every ~30 days during domain contact)"
                            },
                            isInformational: false);

                        // Warning if password hasn't been updated in more than 45 days
                        if (daysSinceUpdate > 45)
                        {
                            _logger.LogWarning(
                                "Computer password update is overdue: {DaysSinceUpdate} days since last update (expected ~30 days)",
                                daysSinceUpdate);
                            
                            TrackTelemetryEvent(
                                "ComputerPasswordUpdateOverdue",
                                new Dictionary<string, string?>
                                {
                                    ["DaysSinceUpdate"] = daysSinceUpdate.ToString(),
                                    ["LastUpdateUTC"] = utcTime.ToString("yyyy-MM-dd HH:mm:ss")
                                },
                                isInformational: false);
                        }
                    }
                    else
                    {
                        string errorMessage = "FileTime value is zero — password may never have been set";
                        _logger.LogError("Computer password update check: {Message}", errorMessage);
                        
                        TrackTelemetryEvent(
                            "ComputerPasswordUpdateCheckFailed",
                            new Dictionary<string, string?>
                            {
                                ["Error"] = errorMessage,
                                ["Reason"] = "FileTime value is zero"
                            },
                            isInformational: false);
                    }
                }
                else
                {
                    string errorMessage = "Registry value is empty or too short";
                    _logger.LogError("Computer password update check: {Message}", errorMessage);
                    
                    TrackTelemetryEvent(
                        "ComputerPasswordUpdateCheckFailed",
                        new Dictionary<string, string?>
                        {
                            ["Error"] = errorMessage,
                            ["Reason"] = "Value empty or insufficient bytes"
                        },
                        isInformational: false);
                }
            }
            catch (UnauthorizedAccessException ex)
            {
                _logger.LogError(ex, "Access denied reading SECURITY hive. Service must run as SYSTEM.");
                
                TrackTelemetryEvent(
                    "ComputerPasswordUpdateCheckFailed",
                    new Dictionary<string, string?>
                    {
                        ["Error"] = "Access denied",
                        ["Reason"] = "Service must run as SYSTEM to access SECURITY hive",
                        ["ExceptionType"] = ex.GetType().Name
                    },
                    isInformational: false);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Exception occurred while checking computer password update");
                
                TrackTelemetryEvent(
                    "ComputerPasswordUpdateCheckException",
                    new Dictionary<string, string?>
                    {
                        ["Error"] = ex.Message,
                        ["ExceptionType"] = ex.GetType().Name
                    },
                    isInformational: false);
            }
        }
    }
}
