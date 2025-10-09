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
        /// Checks and logs the active user status.
        /// </summary>
        private void CheckAndLogActiveUser()
        {
            var activeUser = GetActiveUser();
            if (_kioskUsers == null || _kioskUsers.Count == 0)
            {
                if (_verboseLoggingLocal)
                    _logger.LogInformation("KioskUser list not configured. Skipping active user check.");
                return;
            }

            bool match = _kioskUsers.Any(u => string.Equals(activeUser, u, StringComparison.OrdinalIgnoreCase));
            if (match)
            {
                _logger.LogInformation("Kiosk user '{ActiveUser}' is currently active.", activeUser);
                TrackTelemetryEvent(
                    "KioskUserActive",
                    new Dictionary<string, string?>
                    {
                        ["ActiveUser"] = activeUser,
                        ["KioskUsers"] = string.Join(";", _kioskUsers)
                    },
                    isInformational: true);
            }
            else
            {
                _logger.LogWarning("Active user '{ActiveUser}' does not match any KioskUser.", activeUser);
                TrackTelemetryEvent(
                    "KioskUserMismatch",
                    new Dictionary<string, string?>
                    {
                        ["ActiveUser"] = activeUser,
                        ["KioskUsers"] = string.Join(";", _kioskUsers)
                    },
                    isInformational: false);
            }
        }
    }
}
