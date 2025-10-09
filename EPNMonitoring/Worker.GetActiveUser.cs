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
        /// Gets the currently active user.
        /// </summary>
        private string GetActiveUser()
        {
            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_ComputerSystem");
                foreach (var obj in searcher.Get())
                {
                    var user = obj["UserName"]?.ToString();
                    if (!string.IsNullOrWhiteSpace(user))
                        return user;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get active user.");
            }
            return string.Empty;
        }
    }
}
