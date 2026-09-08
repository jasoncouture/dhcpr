using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Net;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;

using Microsoft.Extensions.DependencyInjection;

using NSubstitute;

namespace Dhcpr.Dns.Core.UnitTests;

public class DnsInstrumentationTests
{
    [Fact]
    public void StartQueryTagsQuestionAndPeer()
    {
        var started = new Started();
        using var listener = ListenFor(DnsInstrumentation.QuerySpanName, started);

        var request = DomainMessage.CreateRequest("example.com", DomainRecordType.AAAA);
        var context = new DomainMessageContext(
            new IPEndPoint(IPAddress.Parse("203.0.113.10"), 53_000),
            new IPEndPoint(IPAddress.Loopback, 53),
            request);
        var message = new HttpDnsPacketReceivedMessage(context);

        using var activity = DnsInstrumentation.StartQuery(message);

        Assert.NotNull(activity);
        Assert.True(started.Value);
        Assert.Equal("example.com", activity!.GetTagItem("dns.question.name"));
        Assert.Equal(nameof(DomainRecordType.AAAA), activity.GetTagItem("dns.question.type"));
        Assert.Equal("doh", activity.GetTagItem("network.transport"));
        Assert.Equal("203.0.113.10", activity.GetTagItem("network.peer.address"));
    }

    [Fact]
    public void CompleteQueryMarksServFail()
    {
        using var listener = ListenFor(DnsInstrumentation.QuerySpanName, new Started());

        var request = DomainMessage.CreateRequest("example.com");
        var response = DomainMessage.CreateResponse(request, responseCode: DomainResponseCode.ServerFailure);
        var context = new DomainMessageContext(
            new IPEndPoint(IPAddress.Loopback, 53000),
            new IPEndPoint(IPAddress.Loopback, 53),
            request)
        {
            ServFailReason = "no reachable nameserver",
            CacheHit = false,
            AnsweredBy = "RecursiveRootResolver"
        };

        using var activity = DnsInstrumentation.StartQuery(new HttpDnsPacketReceivedMessage(context));
        DnsInstrumentation.CompleteQuery(activity, context, response);

        Assert.Equal(ActivityStatusCode.Error, activity!.Status);
        Assert.Equal("no reachable nameserver", activity.StatusDescription);
        Assert.Equal(nameof(DomainResponseCode.ServerFailure), activity.GetTagItem("dns.response.code"));
        Assert.Equal("RecursiveRootResolver", activity.GetTagItem("dhcpr.answered_by"));
    }

    [Fact]
    public void StartQueryUsesParentTraceContext()
    {
        using var listener = ListenFor(DnsInstrumentation.InternalSpanName, new Started());

        using var parent = DnsInstrumentation.ActivitySource.StartActivity("parent");
        Assert.NotNull(parent);

        var request = DomainMessage.CreateRequest("com");
        var context = new DomainMessageContext(
            new IPEndPoint(IPAddress.Loopback, 53000),
            new IPEndPoint(IPAddress.Loopback, 53),
            request)
        {
            IsInternal = true,
            ParentTraceContext = parent!.Context
        };

        using var activity = DnsInstrumentation.StartQuery(new HttpDnsPacketReceivedMessage(context));

        Assert.NotNull(activity);
        Assert.Equal(parent.TraceId, activity!.TraceId);
        Assert.Equal(parent.SpanId, activity.ParentSpanId);
    }

    [Fact]
    public void RecordDurationSkipsInternalAndBypass()
    {
        double observed = 0;
        using var meterListener = CreateDurationListener(value => observed += value);
        var histogram = CreateDurationHistogram();

        var request = DomainMessage.CreateRequest("example.com");
        var response = DomainMessage.CreateResponse(request);
        var internalContext = new DomainMessageContext(
            new IPEndPoint(IPAddress.Loopback, 53000),
            new IPEndPoint(IPAddress.Loopback, 53),
            request)
        {
            IsInternal = true
        };
        var bypassContext = new DomainMessageContext(
            new IPEndPoint(IPAddress.Loopback, 53000),
            new IPEndPoint(IPAddress.Loopback, 53),
            request)
        {
            BypassCache = true
        };

        DnsInstrumentation.RecordDuration(histogram, internalContext, response, TimeSpan.FromMilliseconds(5));
        DnsInstrumentation.RecordDuration(histogram, bypassContext, response, TimeSpan.FromMilliseconds(5));

        Assert.Equal(0, observed);
    }

    [Fact]
    public void RecordDurationCountsClientAnswers()
    {
        double observed = 0;
        using var meterListener = CreateDurationListener(value => observed += value);
        var histogram = CreateDurationHistogram();

        var request = DomainMessage.CreateRequest("example.com");
        var response = DomainMessage.CreateResponse(request);
        var context = new DomainMessageContext(
            new IPEndPoint(IPAddress.Loopback, 53000),
            new IPEndPoint(IPAddress.Loopback, 53),
            request);

        DnsInstrumentation.RecordDuration(histogram, context, response, TimeSpan.FromMilliseconds(25));

        Assert.True(observed > 0);
    }

    [Fact]
    public async Task TracingDomainClientCreatesUpstreamSpan()
    {
        var started = new Started();
        using var listener = ListenFor(DnsInstrumentation.UpstreamSpanName, started);

        var request = DomainMessage.CreateRequest("example.com");
        var response = DomainMessage.CreateResponse(request);
        var inner = Substitute.For<IDomainClient>();
        inner.SendAsync(Arg.Any<DomainMessage>(), Arg.Any<CancellationToken>())
            .Returns(_ => new ValueTask<DomainMessage>(response));

        var client = new TracingDomainClient(inner, new IPEndPoint(IPAddress.Parse("192.0.2.53"), 53), "udp");
        var result = await client.SendAsync(request, CancellationToken.None);

        Assert.Same(response, result);
        Assert.True(started.Value);
    }

    private sealed class Started
    {
        public bool Value;
    }

    private static ActivityListener ListenFor(string spanName, Started started)
    {
        var listener = new ActivityListener
        {
            ShouldListenTo = source => source.Name == DnsInstrumentation.ActivitySourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStarted = activity =>
            {
                if (activity.OperationName == spanName)
                    started.Value = true;
            }
        };
        ActivitySource.AddActivityListener(listener);
        return listener;
    }

    private static Histogram<double> CreateDurationHistogram()
    {
        var services = new ServiceCollection();
        services.AddMetrics();
        var meter = services.BuildServiceProvider().GetRequiredService<IMeterFactory>()
            .Create(DnsMetrics.MeterName);
        return meter.CreateHistogram<double>(DnsMetrics.DurationInstrumentName, unit: "s");
    }

    private static MeterListener CreateDurationListener(Action<double> onMeasurement)
    {
        var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, meterListener) =>
        {
            if (instrument.Meter.Name == DnsMetrics.MeterName &&
                instrument.Name == DnsMetrics.DurationInstrumentName)
            {
                meterListener.EnableMeasurementEvents(instrument);
            }
        };
        listener.SetMeasurementEventCallback<double>((_, measurement, _, _) => onMeasurement(measurement));
        listener.Start();
        return listener;
    }
}
