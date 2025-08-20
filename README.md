# EPNMonitoring

EPNMonitoring is a .NET 8 Worker Service designed for automated monitoring and telemetry of various system and application health aspects. It is intended for use on Windows systems and leverages Application Insights for telemetry, as well as local logging for diagnostics and auditing.

## Features

- **Process Monitoring:** Ensures specified processes are running based on a configurable list and interval.
- **Crash Report Monitoring:** Detects, archives, and moves application crash reports from a designated folder.
- **Windows License Monitoring:** Checks Windows edition, verifies KMS key, enables activation, and can restart after activation.
- **Website Monitoring:** Periodically checks connectivity to configured websites.
- **Event Viewer Monitoring:** Scans Windows Event Viewer for events from specified applications.
- **Device Monitoring:** Verifies presence of specified hardware devices at set intervals.
- **Port Tests:** Tests connectivity to specified ports on configured servers.
- **Kiosk User Monitoring:** Checks for the presence of configured kiosk user accounts.
- **Default Printer Monitoring:** Ensures the default printer is set and can force the setting if required.
- **Verbose Logging:** Configurable logging to local file and Application Insights, with verbosity options for each.
- **Local Log Management:** Maintains a local log file with autoclean and maximum size options.
- **Update Log File:** Records Windows update logs to a specified file.

---

## Configuration (`appsettings.json`)

Below is a description of each configuration section and its parameters, based on the current `appsettings.json`:

---

### Logging
```json
"Logging": {
  "LogLevel": {
    "Default": "Information",
    "Microsoft.Hosting.Lifetime": "Information"
  }
}
```
- **LogLevel:** Sets the minimum log level for the application and host lifetime events.

---

### ApplicationInsights
```json
"ApplicationInsights": {
  "ConnectionString": "APP_INSIGHTS_CONNECTION_STRING",
  "EnableAdaptiveSampling": true,
  "EnablePerformanceCounterCollectionModule": true,
  "EnableQuickPulseMetricStream": false,
  "EnableDependencyTrackingTelemetryModule": false,
  "EnableAppServicesHeartbeatTelemetryModule": false,
  "EnableAzureInstanceMetadataTelemetryModule": false,
  "EnableEventCounterCollectionModule": false,
  "EnableHeartbeat": true,
  "EnableLiveMetrics": false,
  "EnableRequestTrackingTelemetryModule": false,
  "EnableWindowsHeartbeatTelemetryModule": false,
  "EnableDiagnosticsTelemetryModule": true,
  "EnableInternalTelemetry": true
}
```
- **ConnectionString:** Application Insights connection string.
- **Enable*:** Flags to enable/disable specific Application Insights modules and features.

---

### ProcessMonitor
```json
"ProcessMonitor": {
  "Enabled": true,
  "CheckIntervalSeconds": 30,
  "Executables": [
    "notepad"
  ]
}
```
- **Enabled:** Enable/disable process monitoring.
- **CheckIntervalSeconds:** Interval for checking running processes.
- **Executables:** List of process names (without `.exe`) to monitor.

---

### CrashReportMonitor
```json
"CrashReportMonitor": {
  "Enabled": true,
  "FolderPath": "C:\\Users\\vdh_m\\AppData\\Roaming\\Mozilla\\Firefox\\Crash Reports\\pending",
  "CheckIntervalSeconds": 300,
  "DestinationFolder": "C:\\Users\\vdh_m\\AppData\\Roaming\\Mozilla\\Firefox\\Crash Reports\\archived"
}
```
- **Enabled:** Enable/disable crash report monitoring.
- **FolderPath:** Directory to scan for crash reports.
- **CheckIntervalSeconds:** How often to check for new crash reports.
- **DestinationFolder:** Where to move archived crash reports.

---

### WindowsLicenseMonitor
```json
"WindowsLicenseMonitor": {
  "Enabled": true,
  "CheckIntervalSeconds": 30,
  "ExpectedEdition": "Enterprise",
  "KMSKey": "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX",
  "EnableActivation": true,
  "RestartAfterActivation": true
}
```
- **Enabled:** Enable/disable license monitoring.
- **CheckIntervalSeconds:** How often to check Windows license status.
- **ExpectedEdition:** Required Windows edition.
- **KMSKey:** Product key for KMS activation.
- **EnableActivation:** Attempt activation if needed.
- **RestartAfterActivation:** Restart after successful activation.

---

### LocalLog
```json
"LocalLog": {
  "Enabled": true,
  "FilePath": "C:\\temp\\ai-internal.log",
  "MaxLogSize": 10485760,
  "Autoclean": true
}
```
- **Enabled:** Enable/disable local log file.
- **FilePath:** Path to the local log file.
- **MaxLogSize:** Maximum log file size (bytes).
- **Autoclean:** Automatically clean the log file when exceeding max size.

---

### WebsiteMonitor
```json
"WebsiteMonitor": {
  "Enabled": false,
  "CheckIntervalSeconds": 30,
  "Sites": [
    "https://www.microsoft.com",
    "https://1.1.1.1",
    "https://www.github.com"
  ]
}
```
- **Enabled:** Enable/disable website monitoring.
- **CheckIntervalSeconds:** Interval for checking website connectivity.
- **Sites:** List of URLs to monitor.

---

### EventViewerMonitor
```json
"EventViewerMonitor": {
  "Enabled": true,
  "CheckIntervalSeconds": 60,
  "Applications": [
    "notepad.exe"
  ]
}
```
- **Enabled:** Enable/disable Event Viewer monitoring.
- **CheckIntervalSeconds:** How often to scan Event Viewer.
- **Applications:** List of application names to monitor for specific events.

---

### VerboseLogging
```json
"VerboseLogging": {
  "AppInsight": false,
  "Local": true
}
```
- **AppInsight:** Enables verbose logging to Application Insights.
- **Local:** Enables verbose local logging.

---

### DeviceMonitor
```json
"DeviceMonitor": {
  "Enabled": true,
  "Devices": [
    "USB Serial Device",
    "Intel(R) Ethernet Connection"
  ],
  "CheckIntervalSeconds": 60
}
```
- **Enabled:** Enable/disable device monitoring.
- **Devices:** List of device names to check for presence.
- **CheckIntervalSeconds:** How often to check for devices.

---

### PortTestsMonitor
```json
"PortTestsMonitor": {
  "Enabled": true,
  "CheckIntervalSeconds": 20,
  "Servers": [
    {
      "Name": "swrdsupport016",
      "Ports": [3389]
    },
    {
      "Name": "SWLICAPPLI022",
      "Ports": [1688]
    }
  ]
}
```
- **Enabled:** Enable/disable port test monitoring.
- **CheckIntervalSeconds:** How often to test ports.
- **Servers:** List of servers with ports to test.

---

### KioskUser
```json
"KioskUser": {
  "Enabled": true,
  "CheckIntervalSeconds": 30,
  "Users": [
    "VBX\\KioskEPN",
    "VBX\\KioskEPNDev"
  ]
}
```
- **Enabled:** Enable/disable kiosk user monitoring.
- **CheckIntervalSeconds:** How often to check kiosk users.
- **Users:** List of kiosk user accounts to monitor.

---

### DefaultPrinter
```json
"DefaultPrinter": {
  "Enabled": true,
  "Name": "HP96",
  "CheckIntervalSeconds": 60,
  "ForceDefault": true
}
```
- **Enabled:** Enable/disable default printer monitoring.
- **Name:** Name of the default printer.
- **CheckIntervalSeconds:** How often to check the default printer.
- **ForceDefault:** Force setting the default printer if needed.

---

### UpdateLog
```json
"UpdateLog": {
  "FilePath": "C:\\temp\\windows-updates.log"
}
```
- **FilePath:** Path to the Windows update log file.

---

## Usage

1. **Configure `appsettings.json`** with your desired monitoring parameters.
2. **Build and run the service** on a Windows machine with .NET 8 installed.
3. **Monitor logs and Application Insights** for alerts and telemetry.

---

## Requirements

- .NET 8 SDK/Runtime
- Windows OS (for registry, event log, and device monitoring features)
- Application Insights resource (for telemetry)

---

