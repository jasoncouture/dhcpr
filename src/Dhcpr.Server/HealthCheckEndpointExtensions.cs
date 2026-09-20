using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace Dhcpr.Server;

public static class HealthCheckEndpointExtensions
{
    public const string HealthPath = "/health";

    public static IServiceCollection AddDhcprHealthChecks(this IServiceCollection services)
    {
        services.AddHealthChecks()
            .AddCheck<DnsListenersHealthCheck>(
                DnsListenersHealthCheck.Name,
                failureStatus: HealthStatus.Unhealthy,
                tags: ["ready", "live", "dns"])
            .AddCheck<DnsResolveHealthCheck>(
                DnsResolveHealthCheck.Name,
                failureStatus: HealthStatus.Unhealthy,
                tags: ["ready", "dns"]);

        return services;
    }

    public static WebApplication MapDhcprHealthChecks(this WebApplication app)
    {
        app.MapHealthChecks(HealthPath);
        return app;
    }
}
