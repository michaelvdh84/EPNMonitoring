# EPNMonitoring

EPNMonitoring is a .NET 8 Worker Service designed for automated monitoring and telemetry of various system and application health aspects. It is intended for use on Windows systems and leverages Application Insights for telemetry, as well as local logging for diagnostics and auditing.

## Features

- **Process Monitoring:** Ensures specified processes are running.
- **Crash Report Monitoring:** Detects and archives application crash reports.
- **Windows License Monitoring:** Checks Windows edition and can automate KMS activation.
- **Website Monitoring:** Periodically checks connectivity to configured websites.
- **Event Viewer Monitoring:** Scans Windows Event Viewer for specific application events.
- **Device Monitoring:** Verifies presence of specified hardware devices.
- **Port Tests:** Tests connectivity to specified ports on a server.
- **Verbose Logging:** Configurable local and Application Insights logging.
- **Local Log Management:** Maintains and autocleans a local log file.

---

## Configuration (`appsettings.json`)

Below is a description of each configuration section and its parameters:

### Logging
```JSON 
"Logging": { 
	"LogLevel": { 
		"Default": "Information", 
		"Microsoft.Hosting.Lifetime": "Information" 
	} 
},
```

- **LogLevel:** Sets the minimum log level for the application and for the host lifetime events.

---

### ApplicationInsights
```JSON 
"ApplicationInsights": { 
	"InstrumentationKey": "APP__INSIGHTS_CONNECTION__STRING", 
    "EnableDebugLogger": false,
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

},
```
- **ConnectionString:** Application Insights connection string.
- **EnableDebugLogger** and other flags: Enable/disable specific Application Insights modules and features.

---

### ProcessMonitor
```JSON 
  "ProcessMonitor": {
    "CheckIntervalSeconds": 30,
    "Executables": [
      "notepad",
      "firefox"
    ]
  },
```
- **CheckIntervalSeconds:** How often (in seconds) to check for running processes.
- **Executables:** List of process names (without `.exe`) to monitor.

---

### CrashReportMonitor
```JSON 
  "CrashReportMonitor": {
    "FolderPath": "C:\\Users\\vdh_m\\AppData\\Roaming\\Mozilla\\Firefox\\Crash Reports\\pending",
    "CheckIntervalSeconds": 300,
    "DestinationFolder": "C:\\Users\\vdh_m\\AppData\\Roaming\\Mozilla\\Firefox\\Crash Reports\\archived"
  },
```
- **FolderPath:** Directory to scan for Firefox crash reports.
- **CheckIntervalSeconds:** How often to check for new crash reports.
- **DestinationFolder:** Where to move archived crash reports.

---

### WindowsLicenseMonitor
```JSON 
  "WindowsLicenseMonitor": {
    "CheckIntervalSeconds": 300,
    "ExpectedEdition": "Enterprise",
    "KMSKey": "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX",
    "EnableActivation": true,
    "RestartAfterActivation": true
  },
```
- **CheckIntervalSeconds:** How often to check Windows license status.
- **ExpectedEdition:** The required Windows edition (e.g., "Enterprise").
- **KMSKey:** Product key for KMS activation.
- **EnableActivation:** Whether to attempt activation if needed.
- **RestartAfterActivation:** Whether to restart after successful activation.

---

### LocalLog
```JSON 
  "LocalLog": {
    "FilePath": "C:\\temp\\ai-internal.log",
    "MaxLogSize": 10485760,
    "Autoclean": true
  },
```
- **FilePath:** Path to the local log file.
- **MaxLogSize:** Maximum log file size in bytes before autoclean.
- **Autoclean:** Whether to automatically clean the log file when it exceeds the maximum size.

---

### WebsiteMonitor
```JSON 
  "WebsiteMonitor": {
    "CheckIntervalSeconds": 30,
    "Sites": [
      "https://www.microsoft.com",
      "https://1.1.1.1",
      "https://www.github.com"
    ]
  },
```
- **CheckIntervalSeconds:** How often to check website connectivity.
- **Sites:** List of URLs to monitor.

---

### EventViewerMonitor
```JSON 
  "EventViewerMonitor": {
    "CheckIntervalSeconds": 60,
    "Applications": [
      "Firefox",
      "EPNLauncher"
    ]
  },
```
---

### VerboseLogging
```JSON 
  "VerboseLogging": {
    "AppInsight": false,
    "Local": false
  },
```

- **AppInsight:** Enables verbose logging to Application Insights.
- **Local:** Enables verbose local logging.

---

### DeviceMonitor
```JSON 
  "DeviceMonitor": {
    "Devices": [
      "USB Serial Device",
      "Intel(R) Ethernet Connection",
      "NVIDIA GeForce"
    ],
    "CheckIntervalSeconds": 60
  },
```
- **Devices:** List of device names to check for presence.
- **CheckIntervalSeconds:** How often to check for devices.

---

### PortTestsMonitor
```JSON 
  "PortTestsMonitor": {
    "LogonServer": "192.168.8.6",
    "CheckIntervalSeconds": 20,
    "PortTests": [
      { "Title": "DNS", "Port": 53 }
    ]
  },
```
- **LogonServer:** Server to test port connectivity.
- **CheckIntervalSeconds:** How often to run port tests.
- **PortTests:** List of ports (with titles) to test.

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

## License

This project is intended for internal use. See repository for license details.

