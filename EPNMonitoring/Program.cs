using EPNMonitoring;

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddHostedService<Worker>();
builder.Services.AddApplicationInsightsTelemetryWorkerService();


var host = builder.Build();
host.Run();

