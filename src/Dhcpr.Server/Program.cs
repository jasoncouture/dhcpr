using Dhcpr.Core;
using Dhcpr.Dhcp.Core;
using Dhcpr.Dns.Core;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Server;
using Dhcpr.Server.Components;
using Dhcpr.Server.LiveQueries;

using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

using OpenTelemetry.Metrics;

ThreadPool.GetMaxThreads(out var workerMaxThreads, out _);
ThreadPool.GetMinThreads(out var workerMinThreads, out _);
ThreadPool.SetMaxThreads(workerMaxThreads, 16384);
ThreadPool.SetMinThreads(workerMinThreads, 256);

var builder = WebApplication.CreateBuilder(new WebApplicationOptions
{
    Args = args,
    ContentRootPath = AppContext.BaseDirectory,
});

builder.Services.Configure<HostOptions>(options =>
    options.BackgroundServiceExceptionBehavior = BackgroundServiceExceptionBehavior.StopHost);

builder.Services.AddMemoryCache(o =>
{
    o.TrackStatistics = true;
    o.ExpirationScanFrequency = TimeSpan.FromMinutes(5);
});

builder.Services.AddOptionsWithValidateOnStart<ApplicationConfiguration>()
    .Configure<IConfiguration>((options, configuration) => configuration.Bind(options))
    .Validate(static o => o.Validate(), "DataPath must be set");

builder.Services.AddDataProtection().SetApplicationName("dhcpr");

builder.Services.AddOptions<KeyManagementOptions>()
    .Configure<ILoggerFactory, IOptions<ApplicationConfiguration>>((options, loggerFactory, application) =>
    {
        var target = Directory.CreateDirectory(application.Value.GetDataProtectionKeysPath());
        options.XmlRepository = new FileSystemXmlRepository(target, loggerFactory);
    });

builder.Services.AddCoreServices();
builder.Services.AddDns();
builder.Services.AddDhcp();
builder.Services.AddDhcprHealthChecks();

builder.Services.AddSingleton<LiveQueryStore>();
builder.Services.AddHostedService(static sp => sp.GetRequiredService<LiveQueryStore>());
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

builder.Services.AddOpenTelemetry()
    .WithMetrics(metrics =>
    {
        metrics.AddMeter(DnsMetrics.MeterName);
        metrics.AddPrometheusExporter();
    });

var app = builder.Build();

app.UseAntiforgery();
app.MapStaticAssets();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.MapPrometheusScrapingEndpoint();
app.MapDhcprHealthChecks();
app.MapDnsOverHttp();
app.MapDynDnsUpdate();

Console.WriteLine("Application configuration complete, starting services.");
app.Run();

public partial class Program;
