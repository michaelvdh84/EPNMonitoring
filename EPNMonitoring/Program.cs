using EPNMonitoring;
using Microsoft.Extensions.Hosting.WindowsServices;
using Microsoft.Extensions.Logging;

var builder = Host.CreateApplicationBuilder(args);

// Configure optional local file logging based on configuration
var localLogPath = builder.Configuration.GetValue<string>("LocalLog:FilePath");
if (!string.IsNullOrWhiteSpace(localLogPath))
{
    builder.Logging.AddProvider(new FileLoggerProvider(localLogPath));
}


// Enable running as a Windows service so the application can properly
// communicate its status to the Service Control Manager.
builder.Services.AddWindowsService(options =>
{
    options.ServiceName = "EPNMonitoring";
});

builder.Services.AddHostedService<Worker>();
builder.Services.AddApplicationInsightsTelemetryWorkerService();


var host = builder.Build();
host.Run();

