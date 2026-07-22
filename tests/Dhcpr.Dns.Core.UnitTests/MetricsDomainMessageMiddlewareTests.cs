using System.Diagnostics.Metrics;
using System.Net;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;

using Microsoft.Extensions.DependencyInjection;

using NSubstitute;

namespace Dhcpr.Dns.Core.UnitTests;

public class MetricsDomainMessageMiddlewareTests
{
    [Fact]
    public async Task CountsWhenInnerAnswers()
    {
        long observed = 0;
        using var listener = CreateListener(measurement => observed += measurement);

        var request = DomainMessage.CreateRequest("example.com");
        var response = DomainMessage.CreateResponse(request, responseCode: DomainResponseCode.NoError);
        var middleware = CreateMiddleware(response);
        var context = new DomainMessageContext(
            new IPEndPoint(IPAddress.Parse("203.0.113.10"), 53_000),
            new IPEndPoint(IPAddress.Loopback, 53),
            request);

        var result = await middleware.ProcessAsync(context, CancellationToken.None);

        Assert.Same(response, result);
        Assert.Equal(1, observed);
    }

    [Fact]
    public async Task DoesNotCountCoRPassThrough()
    {
        long observed = 0;
        using var listener = CreateListener(measurement => observed += measurement);

        var middleware = CreateMiddleware(response: null);
        var context = new DomainMessageContext(
            new IPEndPoint(IPAddress.Parse("203.0.113.10"), 53_000),
            new IPEndPoint(IPAddress.Loopback, 53),
            DomainMessage.CreateRequest("example.com"));

        var result = await middleware.ProcessAsync(context, CancellationToken.None);

        Assert.Null(result);
        Assert.Equal(0, observed);
    }

    [Fact]
    public async Task CountsInternalAnswers()
    {
        long observed = 0;
        using var listener = CreateListener(measurement => observed += measurement);

        var request = DomainMessage.CreateRequest("example.com");
        var response = DomainMessage.CreateResponse(request, responseCode: DomainResponseCode.NoError);
        var middleware = CreateMiddleware(response);
        var context = new DomainMessageContext(
            new IPEndPoint(IPAddress.Parse("203.0.113.10"), 53_000),
            new IPEndPoint(IPAddress.Loopback, 53),
            request)
        {
            IsInternal = true
        };

        await middleware.ProcessAsync(context, CancellationToken.None);

        Assert.Equal(1, observed);
    }

    private static MetricsDomainMessageMiddleware CreateMiddleware(DomainMessage? response)
    {
        var inner = Substitute.For<IDomainMessageMiddleware>();
        inner.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(_ => new ValueTask<DomainMessage?>(response));

        var services = new ServiceCollection();
        services.AddMetrics();
        return new MetricsDomainMessageMiddleware(
            inner,
            services.BuildServiceProvider().GetRequiredService<IMeterFactory>());
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
