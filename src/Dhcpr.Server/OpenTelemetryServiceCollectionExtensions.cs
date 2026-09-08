using Dhcpr.Dhcp.Core;
using Dhcpr.Dns.Core.Protocol.Processing;

using OpenTelemetry;
using OpenTelemetry.Metrics;
using OpenTelemetry.Trace;

namespace Dhcpr.Server;

public static class OpenTelemetryServiceCollectionExtensions
{
    public static WebApplicationBuilder AddDhcprOpenTelemetry(this WebApplicationBuilder builder)
    {
        builder.Services.AddOpenTelemetry()
            .WithMetrics(metrics =>
            {
                metrics.AddMeter(DnsMetrics.MeterName);
                metrics.AddMeter(DhcpInstrumentation.MeterName);
                metrics.AddAspNetCoreInstrumentation();
                metrics.AddHttpClientInstrumentation();
                metrics.AddRuntimeInstrumentation();
                metrics.AddPrometheusExporter();
            })
            .WithTracing(tracing =>
            {
                tracing.AddSource(DnsInstrumentation.ActivitySourceName);
                tracing.AddSource(DhcpInstrumentation.ActivitySourceName);
                tracing.AddAspNetCoreInstrumentation(options =>
                {
                    options.Filter = static context =>
                    {
                        var path = context.Request.Path;
                        return !path.StartsWithSegments("/health") &&
                               !path.StartsWithSegments("/metrics");
                    };
                });
                tracing.AddHttpClientInstrumentation();
            })
            .WithLogging(
                configureBuilder: null,
                configureOptions: options =>
                {
                    options.IncludeFormattedMessage = true;
                    options.IncludeScopes = true;
                    options.ParseStateValues = true;
                })
            .UseOtlpExporter();

        return builder;
    }
}
