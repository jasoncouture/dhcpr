using System.Diagnostics.Metrics;
using System.Net;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;

using Microsoft.Extensions.DependencyInjection;

namespace Dhcpr.Dns.Core.UnitTests;

public class MetricsDomainMessageMiddlewareTests
{
    [Fact]
    public async Task CountsExternalQueries()
    {
        long observed = 0;
        using var listener = CreateListener(measurement => observed += measurement);

        var middleware = CreateMiddleware();
        var context = new DomainMessageContext(
            new IPEndPoint(IPAddress.Parse("203.0.113.10"), 53_000),
            new IPEndPoint(IPAddress.Loopback, 53),
            DomainMessage.CreateRequest("example.com"));

        var result = await middleware.ProcessAsync(context, CancellationToken.None);

        Assert.Null(result);
        Assert.Equal(1, observed);
    }

    [Fact]
    public async Task IgnoresInternalRecursiveRequests()
    {
        long observed = 0;
        using var listener = CreateListener(measurement => observed += measurement);

        var middleware = CreateMiddleware();
        var context = new DomainMessageContext(
            new IPEndPoint(IPAddress.Parse("203.0.113.10"), 53_000),
            new IPEndPoint(IPAddress.Loopback, 53),
            DomainMessage.CreateRequest("example.com"))
        {
            IsInternal = true
        };

        await middleware.ProcessAsync(context, CancellationToken.None);

        Assert.Equal(0, observed);
    }

    private static MetricsDomainMessageMiddleware CreateMiddleware()
    {
        var services = new ServiceCollection();
        services.AddMetrics();
        return new MetricsDomainMessageMiddleware(services.BuildServiceProvider().GetRequiredService<IMeterFactory>());
    }

    private static MeterListener CreateListener(Action<long> onMeasurement)
    {
        var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, meterListener) =>
        {
            if (instrument.Meter.Name == DnsMetrics.MeterName &&
                instrument.Name == DnsMetrics.QueriesInstrumentName)
            {
                meterListener.EnableMeasurementEvents(instrument);
            }
        };
        listener.SetMeasurementEventCallback<long>((_, measurement, _, _) => onMeasurement(measurement));
        listener.Start();
        return listener;
    }
}
