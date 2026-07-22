using Dhcpr.Core;
using Dhcpr.Dhcp.Core;
using Dhcpr.Dns.Core;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Server;

using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.Extensions.Options;

using OpenTelemetry.Metrics;

ThreadPool.GetMaxThreads(out var workerMaxThreads, out _);
ThreadPool.GetMinThreads(out var workerMinThreads, out _);
ThreadPool.SetMaxThreads(workerMaxThreads, 16384);
ThreadPool.SetMinThreads(workerMinThreads, 256);

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddMemoryCache(o =>
{
    o.TrackStatistics = true;
    o.ExpirationScanFrequency = TimeSpan.FromMinutes(5);
});

builder.Services.AddOptionsWithValidateOnStart<DataProtectionKeyOptions>()
    .BindConfiguration("DataProtection:Keys");

builder.Services.AddDataProtection().SetApplicationName("dhcpr");

builder.Services.AddOptions<KeyManagementOptions>()
    .Configure<ILoggerFactory, IOptions<DataProtectionKeyOptions>>((options, loggerFactory, keyOptions) =>
    {
        if (string.IsNullOrWhiteSpace(keyOptions.Value.Path)) return;
        var target = Directory.CreateDirectory(keyOptions.Value.Path);
        options.XmlRepository = new FileSystemXmlRepository(target, loggerFactory);
    });

builder.Services.AddCoreServices();
builder.Services.AddDns();
builder.Services.AddDhcp();

builder.Services.AddOpenTelemetry()
    .WithMetrics(metrics =>
    {
        metrics.AddMeter(DnsMetrics.MeterName);
        metrics.AddPrometheusExporter();
    });

var app = builder.Build();

app.MapPrometheusScrapingEndpoint();

Console.WriteLine("Application configuration complete, starting services.");
app.Run();
