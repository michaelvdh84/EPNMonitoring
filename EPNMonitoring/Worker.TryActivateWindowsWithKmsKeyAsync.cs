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
        /// Attempts to activate Windows using the provided KMS key.
        /// </summary>
        private async Task<(bool Success, string Message)> TryActivateWindowsWithKmsKeyAsync(string kmsKey, CancellationToken stoppingToken)
        {
            try
            {
                // Set KMS key
                var setKey = await RunProcessAsync("cscript.exe", $"//Nologo slmgr.vbs /ipk {kmsKey}", stoppingToken);
                if (!setKey.Success)
                    return (false, $"Failed to set KMS key: {setKey.Message}");

                // Activate Windows
                var activate = await RunProcessAsync("cscript.exe", "//Nologo slmgr.vbs /ato", stoppingToken);
                if (!activate.Success)
                    return (false, $"Activation failed: {activate.Message}");

                return (true, "Activation succeeded.");
            }
            catch (Exception ex)
            {
                return (false, $"Exception during activation: {ex.Message}");
            }
        }
    }
}
