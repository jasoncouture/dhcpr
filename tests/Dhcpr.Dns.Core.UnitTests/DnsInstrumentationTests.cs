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
    public void StartQueryTagsDotFromContextSource()
    {
        var started = new Started();
        using var listener = ListenFor(DnsInstrumentation.QuerySpanName, started);

        var request = DomainMessage.CreateRequest("example.com");
        var context = new DomainMessageContext(
            new IPEndPoint(IPAddress.Parse("203.0.113.10"), 53_000),
            new IPEndPoint(IPAddress.Loopback, 853),
            request)
        {
            Source = DnsQuerySource.Dot
        };

        using var activity = DnsInstrumentation.StartQuery(
            new TcpDnsPacketReceivedMessage(context, new System.Net.Sockets.TcpClient(), Stream.Null));

        Assert.NotNull(activity);
        Assert.True(started.Value);
        Assert.Equal("dot", activity!.GetTagItem("network.transport"));
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
    public void RecordDurationTagsSource()
    {
        string? source = null;
        using var meterListener = CreateDurationListener((_, tags) =>
        {
            foreach (var tag in tags)
            {
                if (tag.Key == "source")
                    source = tag.Value?.ToString();
            }
        });
        var histogram = CreateDurationHistogram();
        var request = DomainMessage.CreateRequest("example.com");
        var response = DomainMessage.CreateResponse(request);
        var context = new DomainMessageContext(
            new IPEndPoint(IPAddress.Parse("203.0.113.10"), 53000),
            new IPEndPoint(IPAddress.Loopback, 853),
            request)
        {
            Source = DnsQuerySource.Dot
        };

        DnsInstrumentation.RecordDuration(histogram, context, response, TimeSpan.FromMilliseconds(25));

        Assert.Equal("DoT", source);
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

        var client = new TracingDomainClient(
            inner,
            new IPEndPoint(IPAddress.Parse("192.0.2.53"), 53),
            "udp",
            CreateUpstreamMetrics());
        var result = await client.SendAsync(request, CancellationToken.None);

        Assert.Same(response, result);
        Assert.True(started.Value);
    }

    [Fact]
    public async Task TracingDomainClientCancellationIsNotError()
    {
        Activity? stopped = null;
        using var listener = new ActivityListener
        {
            ShouldListenTo = source => source.Name == DnsInstrumentation.ActivitySourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = activity =>
            {
                if (activity.OperationName == DnsInstrumentation.UpstreamSpanName)
                    stopped = activity;
            }
        };
        ActivitySource.AddActivityListener(listener);

        var inner = Substitute.For<IDomainClient>();
        inner.SendAsync(Arg.Any<DomainMessage>(), Arg.Any<CancellationToken>())
            .Returns<DomainMessage>(_ => throw new OperationCanceledException());

        var client = new TracingDomainClient(
            inner,
            new IPEndPoint(IPAddress.Parse("192.0.2.53"), 53),
            "udp",
            CreateUpstreamMetrics());
        await Assert.ThrowsAsync<OperationCanceledException>(async () =>
            await client.SendAsync(DomainMessage.CreateRequest("example.com"), CancellationToken.None));

        Assert.NotNull(stopped);
        Assert.Equal(ActivityStatusCode.Unset, stopped!.Status);
        Assert.Equal(true, stopped.GetTagItem("dhcpr.cancelled"));
    }

    [Fact]
    public async Task TracingDomainClientRecordsSuccessUpstreamMetrics()
    {
        var seen = new UpstreamObservation();
        using var meterListener = CreateUpstreamListener(seen);
        var metrics = CreateUpstreamMetrics();

        var request = DomainMessage.CreateRequest("example.com", DomainRecordType.NS);
        var response = DomainMessage.CreateResponse(request, responseCode: DomainResponseCode.NoError);
        var inner = Substitute.For<IDomainClient>();
        inner.SendAsync(Arg.Any<DomainMessage>(), Arg.Any<CancellationToken>())
            .Returns(_ => new ValueTask<DomainMessage>(response));

        var client = new TracingDomainClient(
            inner,
            new IPEndPoint(IPAddress.Parse("192.0.2.53"), 53),
            "udp",
            metrics);
        await client.SendAsync(request, CancellationToken.None);

        Assert.Equal(1, seen.DurationCount);
        Assert.Equal(1, seen.QueryCount);
        Assert.True(seen.LastDurationSeconds >= 0);
        Assert.Equal("udp", seen.Transport);
        Assert.Equal(false, seen.Error);
        Assert.Equal(false, seen.Cancelled);
        Assert.Equal(nameof(DomainResponseCode.NoError), seen.Rcode);
        Assert.Equal(nameof(DomainRecordType.NS), seen.QueryType);
    }

    [Fact]
    public async Task TracingDomainClientRecordsRaceCancelWithoutError()
    {
        var seen = new UpstreamObservation();
        using var meterListener = CreateUpstreamListener(seen);
        var metrics = CreateUpstreamMetrics();

        var inner = Substitute.For<IDomainClient>();
        inner.SendAsync(Arg.Any<DomainMessage>(), Arg.Any<CancellationToken>())
            .Returns<DomainMessage>(_ => throw new OperationCanceledException());

        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        var client = new TracingDomainClient(
            inner,
            new IPEndPoint(IPAddress.Parse("192.0.2.53"), 53),
            "udp",
            metrics);
        await Assert.ThrowsAsync<OperationCanceledException>(async () =>
            await client.SendAsync(DomainMessage.CreateRequest("example.com"), cancelled.Token));

        Assert.Equal(1, seen.QueryCount);
        Assert.Equal(false, seen.Error);
        Assert.Equal(true, seen.Cancelled);
        Assert.Equal(DnsMetrics.NoneRcode, seen.Rcode);
    }

    [Fact]
    public async Task TracingDomainClientRecordsTimeoutAsError()
    {
        var seen = new UpstreamObservation();
        using var meterListener = CreateUpstreamListener(seen);
        var metrics = CreateUpstreamMetrics();

        var inner = Substitute.For<IDomainClient>();
        inner.SendAsync(Arg.Any<DomainMessage>(), Arg.Any<CancellationToken>())
            .Returns<DomainMessage>(_ => throw new OperationCanceledException());

        var client = new TracingDomainClient(
            inner,
            new IPEndPoint(IPAddress.Parse("192.0.2.53"), 53),
            "tcp",
            metrics);
        await Assert.ThrowsAsync<OperationCanceledException>(async () =>
            await client.SendAsync(
                DomainMessage.CreateRequest("example.com", DomainRecordType.DNSKEY),
                CancellationToken.None));

        Assert.Equal(1, seen.QueryCount);
        Assert.Equal("tcp", seen.Transport);
        Assert.Equal(true, seen.Error);
        Assert.Equal(false, seen.Cancelled);
        Assert.Equal(DnsMetrics.NoneRcode, seen.Rcode);
        Assert.Equal(nameof(DomainRecordType.DNSKEY), seen.QueryType);
    }

    [Fact]
    public async Task TracingDomainClientRecordsExceptionAsError()
    {
        var seen = new UpstreamObservation();
        using var meterListener = CreateUpstreamListener(seen);
        var metrics = CreateUpstreamMetrics();

        var inner = Substitute.For<IDomainClient>();
        inner.SendAsync(Arg.Any<DomainMessage>(), Arg.Any<CancellationToken>())
            .Returns<DomainMessage>(_ => throw new IOException("upstream reset"));

        var client = new TracingDomainClient(
            inner,
            new IPEndPoint(IPAddress.Parse("192.0.2.53"), 53),
            "udp",
            metrics);
        await Assert.ThrowsAsync<IOException>(async () =>
            await client.SendAsync(DomainMessage.CreateRequest("example.com"), CancellationToken.None));

        Assert.Equal(1, seen.QueryCount);
        Assert.Equal(true, seen.Error);
        Assert.Equal(false, seen.Cancelled);
        Assert.Equal(DnsMetrics.NoneRcode, seen.Rcode);
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
        => CreateDurationListener((measurement, _) => onMeasurement(measurement));

    private static MeterListener CreateDurationListener(
        Action<double, ReadOnlySpan<KeyValuePair<string, object?>>> onMeasurement)
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
        listener.SetMeasurementEventCallback<double>((_, measurement, tags, _) =>
            onMeasurement(measurement, tags));
        listener.Start();
        return listener;
    }

    private sealed class UpstreamObservation
    {
        public int DurationCount;
        public int QueryCount;
        public double LastDurationSeconds;
        public string? Transport;
        public bool? Error;
        public bool? Cancelled;
        public string? Rcode;
        public string? QueryType;
    }

    private static DnsUpstreamMetrics CreateUpstreamMetrics()
    {
        var services = new ServiceCollection();
        services.AddMetrics();
        return new DnsUpstreamMetrics(services.BuildServiceProvider().GetRequiredService<IMeterFactory>());
    }

    private static MeterListener CreateUpstreamListener(UpstreamObservation seen)
    {
        var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, meterListener) =>
        {
            if (instrument.Meter.Name != DnsMetrics.MeterName)
                return;
            if (instrument.Name is DnsMetrics.UpstreamDurationInstrumentName
                or DnsMetrics.UpstreamQueriesInstrumentName)
                meterListener.EnableMeasurementEvents(instrument);
        };
        listener.SetMeasurementEventCallback<double>((instrument, measurement, tags, _) =>
        {
            if (instrument.Name != DnsMetrics.UpstreamDurationInstrumentName)
                return;
            seen.DurationCount++;
            seen.LastDurationSeconds = measurement;
            ReadUpstreamTags(tags, seen);
        });
        listener.SetMeasurementEventCallback<long>((instrument, measurement, tags, _) =>
        {
            if (instrument.Name != DnsMetrics.UpstreamQueriesInstrumentName)
                return;
            seen.QueryCount += (int)measurement;
            ReadUpstreamTags(tags, seen);
        });
        listener.Start();
        return listener;
    }

    private static void ReadUpstreamTags(
        ReadOnlySpan<KeyValuePair<string, object?>> tags,
        UpstreamObservation seen)
    {
        foreach (var tag in tags)
        {
            switch (tag.Key)
            {
                case "network.transport":
                    seen.Transport = tag.Value?.ToString();
                    break;
                case "error":
                    seen.Error = tag.Value is true;
                    break;
                case "cancelled":
                    seen.Cancelled = tag.Value is true;
                    break;
                case "rcode":
                    seen.Rcode = tag.Value?.ToString();
                    break;
                case "query_type":
                    seen.QueryType = tag.Value?.ToString();
                    break;
            }
        }
    }
}
