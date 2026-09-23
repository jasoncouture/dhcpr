using System.Diagnostics.Metrics;

using Dhcpr.Dhcp.Core;
using Dhcpr.Dns.Core.Protocol.Processing;

using OpenTelemetry;
using OpenTelemetry.Logs;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;

namespace Dhcpr.Server;

public static class OpenTelemetryServiceCollectionExtensions
{
    public static WebApplicationBuilder AddDhcprOpenTelemetry(this WebApplicationBuilder builder)
    {
        builder.Services.AddOpenTelemetry()
            .ConfigureResource(resource => resource.AddService("dhcpr"))
            .WithMetrics(metrics =>
            {
                metrics.AddMeter(DnsMetrics.MeterName);
                metrics.AddMeter(DhcpInstrumentation.MeterName);
                // Every duration histogram is in seconds. The SDK default starts
                // at 5 ms, so a faster sample is drawn near the middle of that bucket.
                metrics.AddView(static instrument =>
                    instrument is Histogram<double> { Unit: "s" }
                        ? new ExplicitBucketHistogramConfiguration
                        {
                            Boundaries = DnsMetrics.DurationSecondsBuckets
                        }
                        : null);
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
                tracing.AddOtlpExporter();
            })
            .WithLogging(
                configureBuilder: logging => logging.AddOtlpExporter(),
                configureOptions: options =>
                {
                    options.IncludeFormattedMessage = true;
                    options.IncludeScopes = true;
                    options.ParseStateValues = true;
                });

        return builder;
    }
}
