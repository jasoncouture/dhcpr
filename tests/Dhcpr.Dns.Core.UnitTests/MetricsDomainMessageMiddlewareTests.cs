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

    [Fact]
    public async Task DoesNotCountBypassCacheAnswers()
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
            BypassCache = true
        };

        var result = await middleware.ProcessAsync(context, CancellationToken.None);

        Assert.Same(response, result);
        Assert.Equal(0, observed);
    }

    [Fact]
    public async Task CountsBlackholeNxDomain()
    {
        long observed = 0;
        using var listener = CreateListener(measurement => observed += measurement);

        var leaf = Substitute.For<IDomainMessageMiddleware>();
        var monitor = Substitute.For<Microsoft.Extensions.Options.IOptionsMonitor<DnsConfiguration>>();
        monitor.CurrentValue.Returns(new DnsConfiguration { BlackholeDomains = ["dhitc.com"] });
        var blackhole = new BlackholeDomainMiddleware(leaf, monitor);

        var services = new ServiceCollection();
        services.AddMetrics();
        var middleware = new MetricsDomainMessageMiddleware(
            blackhole,
            services.BuildServiceProvider().GetRequiredService<IMeterFactory>());

        var context = new DomainMessageContext(
            new IPEndPoint(IPAddress.Loopback, 53000),
            new IPEndPoint(IPAddress.Loopback, 53),
            DomainMessage.CreateRequest("www.dhitc.com", DomainRecordType.A));

        var result = await middleware.ProcessAsync(context, CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal(DomainResponseCode.NameError, result!.Flags.ResponseCode);
        Assert.Equal(1, observed);
        await leaf.DidNotReceiveWithAnyArgs()
            .ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public void CountsUdpRateLimitRefused()
    {
        string? rcode = null;
        string? answeredBy = null;
        using var listener = CreateListener((_, tags) =>
        {
            foreach (var tag in tags)
            {
                if (tag.Key == "rcode")
                    rcode = tag.Value?.ToString();
                if (tag.Key == "answered_by")
                    answeredBy = tag.Value?.ToString();
            }
        });

        var services = new ServiceCollection();
        services.AddMetrics();
        var queries = services.BuildServiceProvider()
            .GetRequiredService<IMeterFactory>()
            .Create(DnsMetrics.MeterName)
            .CreateCounter<long>(DnsMetrics.QueriesInstrumentName);

        var request = DomainMessage.CreateRequest("cisco.com", DomainRecordType.TXT);
        var response = DomainMessage.CreateResponse(request, responseCode: DomainResponseCode.Refused);
        var context = new DomainMessageContext(
            new IPEndPoint(IPAddress.Parse("203.0.113.10"), 53_000),
            new IPEndPoint(IPAddress.Loopback, 53),
            request)
        {
            AnsweredBy = "UdpRateLimit"
        };

        DnsMetrics.RecordQueries(queries, context, response);

        Assert.Equal(nameof(DomainResponseCode.Refused), rcode);
        Assert.Equal("UdpRateLimit", answeredBy);
    }

    [Fact]
    public void CountsUdpRateLimitDrop()
    {
        string? rcode = null;
        using var listener = CreateListener((_, tags) =>
        {
            foreach (var tag in tags)
            {
                if (tag.Key == "rcode")
                    rcode = tag.Value?.ToString();
            }
        });

        var services = new ServiceCollection();
        services.AddMetrics();
        var queries = services.BuildServiceProvider()
            .GetRequiredService<IMeterFactory>()
            .Create(DnsMetrics.MeterName)
            .CreateCounter<long>(DnsMetrics.QueriesInstrumentName);

        var request = DomainMessage.CreateRequest("cisco.com", DomainRecordType.TXT);
        var context = new DomainMessageContext(
            new IPEndPoint(IPAddress.Parse("203.0.113.10"), 53_000),
            new IPEndPoint(IPAddress.Loopback, 53),
            request)
        {
            AnsweredBy = "UdpRateLimit"
        };

        DnsMetrics.RecordQueries(queries, context, DnsMetrics.DropRcode, error: true);

        Assert.Equal(DnsMetrics.DropRcode, rcode);
    }

    [Fact]
    public async Task TagsRcodeFromResponse()
    {
        string? rcode = null;
        using var listener = CreateListener((_, tags) =>
        {
            foreach (var tag in tags)
            {
                if (tag.Key == "rcode")
                    rcode = tag.Value?.ToString();
            }
        });

        var request = DomainMessage.CreateRequest("missing.example");
        var response = DomainMessage.CreateResponse(request, responseCode: DomainResponseCode.NameError);
        var middleware = CreateMiddleware(response);
        var context = new DomainMessageContext(
            new IPEndPoint(IPAddress.Loopback, 53000),
            new IPEndPoint(IPAddress.Loopback, 53),
            request);

        await middleware.ProcessAsync(context, CancellationToken.None);

        Assert.Equal(nameof(DomainResponseCode.NameError), rcode);
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
        => CreateListener((measurement, _) => onMeasurement.Invoke(measurement));

    private static MeterListener CreateListener(Action<long, ReadOnlySpan<KeyValuePair<string, object?>>> onMeasurement)
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
        listener.SetMeasurementEventCallback<long>((_, measurement, tags, _) =>
            onMeasurement.Invoke(measurement, tags));
        listener.Start();
        return listener;
    }
}
