using EPNMonitoring;
using Microsoft.Extensions.Hosting.WindowsServices;

var builder = Host.CreateApplicationBuilder(args);


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

