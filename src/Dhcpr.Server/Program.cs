using Dhcpr.Core;
using Dhcpr.Dhcp.Core;
using Dhcpr.Dns.Core;
using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Protocol.Processing.LiveQueries;
using Dhcpr.Server;
using Dhcpr.Server.Components;
using Dhcpr.Server.Components.Pages.Admin.Settings;
using Dhcpr.Dns.Core.Resolvers.Caching;
using Dhcpr.Server.Cache;
using Dhcpr.Server.LiveQueries;
using Dhcpr.Server.Orleans.Cache;
using Dhcpr.Server.Orleans.LiveQueries;
using Dhcpr.Server.Settings;

using Dhcpr.Server.Orleans.DataProtection;
using Dhcpr.Server.Orleans.DnsCookies;

using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

using Orleans.Dashboard;

var builder = WebApplication.CreateBuilder();

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
// One ring per process. The grain, the key files, and the repository share it.
builder.Services.AddSingleton<IDataProtectionKeySnapshot, DataProtectionKeySnapshot>();
builder.Services.AddSingleton<IDataProtectionKeyFiles, DataProtectionKeyFiles>();
builder.Services.AddSingleton<IXmlRepository, OrleansDataProtectionKeyRepository>();
builder.Services.AddOptions<KeyManagementOptions>()
    .Configure<IXmlRepository>((options, repository) => options.XmlRepository = repository);

builder.Services.AddCoreServices();
builder.Services.AddDns();
builder.UseTlsCertificateForHttps();
builder.Services.AddDhcprRuntimeSettings();
// One per process. The settings forms share the line and byte parsers.
builder.Services.AddSingleton<ISettingsEdit, SettingsEdit>();
builder.Services.AddDhcp();
builder.Services.AddDhcprHealthChecks();
builder.AddDhcprOrleans();

builder.Services.Replace(ServiceDescriptor.Singleton<ILiveQueryEventPublisher, OrleansLiveQueryEventPublisher>());
builder.Services.AddHostedService(static sp =>
    (OrleansLiveQueryEventPublisher)sp.GetRequiredService<ILiveQueryEventPublisher>());
builder.Services.AddHostedService<LiveQueryOrleansBridge>();
builder.Services.Replace(ServiceDescriptor.Singleton<IDnsCacheEventPublisher, OrleansDnsCacheEventPublisher>());
builder.Services.AddHostedService(static sp =>
    (OrleansDnsCacheEventPublisher)sp.GetRequiredService<IDnsCacheEventPublisher>());
builder.Services.AddHostedService<DnsCacheOrleansBridge>();
builder.Services.AddHostedService<DataProtectionKeyOrleansBridge>();
// One secret per process. The grain, the bridge, and the source share it.
builder.Services.AddSingleton<IDnsServerCookieSecretSnapshot, DnsServerCookieSecretSnapshot>();
builder.Services.Replace(ServiceDescriptor.Singleton<IDnsServerCookieSecretSource, OrleansDnsServerCookieSecretSource>());
builder.Services.AddHostedService<DnsServerCookieSecretOrleansBridge>();
// One per process. The store and the WebSocket session share the probe filter.
builder.Services.AddSingleton<ILiveQueryFilters, LiveQueryFilters>();
builder.Services.AddSingleton<ILiveQueryStore, LiveQueryStore>();
builder.Services.AddHostedService(static sp =>
    (LiveQueryStore)sp.GetRequiredService<ILiveQueryStore>());
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();
builder.AddDhcprAuthentication();

builder.AddDhcprOpenTelemetry();

var app = builder.Build();


app.UseDhcprForwardedHeaders();
app.UseIpv4MappedAddresses();
app.UsePrivateInfrastructureEndpoints();

// DNS Middleware
app.MapDnsOverHttp();
app.MapDynDnsUpdate();
app.UseDohHostIsolation();

// Infrastructure middleware
app.MapPrometheusScrapingEndpoint();
app.MapDhcprHealthChecks();
app.UseWebSockets();

// DNS, DynDNS, /health, and /metrics stay beside the Blazor app.
app.UseStaticFiles();
app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();
app.MapDhcprAccountEndpoints();
app.MapLiveQueryWebSocket();
app.MapStaticAssets();
// Operator pages carry their own [Authorize]. A blanket requirement also
// locks the circuit, so a signed-out visitor would never see the public counter move.
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.MapOrleansDashboard(routePrefix: OidcAuthenticationExtensions.OrleansDashboardPath)
    .RequireAuthorization(OidcAuthenticationExtensions.DnsAdminPolicy);

app.Run();

public partial class Program;
