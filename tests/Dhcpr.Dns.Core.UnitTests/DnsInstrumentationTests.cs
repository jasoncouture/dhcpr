using System.Diagnostics;
using System.Net;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;

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
            request)
        {
            Source = DnsQuerySource.Doh
        };

        using var activity = DnsInstrumentation.StartQuery(context);

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

        using var activity = DnsInstrumentation.StartQuery(context);

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

        using var activity = DnsInstrumentation.StartQuery(context);
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

        using var activity = DnsInstrumentation.StartQuery(context);

        Assert.NotNull(activity);
        Assert.Equal(parent.TraceId, activity!.TraceId);
        Assert.Equal(parent.SpanId, activity.ParentSpanId);
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
            Substitute.For<IDnsMetrics>());
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
            Substitute.For<IDnsMetrics>());
        await Assert.ThrowsAsync<OperationCanceledException>(async () =>
            await client.SendAsync(DomainMessage.CreateRequest("example.com"), CancellationToken.None));

        Assert.NotNull(stopped);
        Assert.Equal(ActivityStatusCode.Unset, stopped!.Status);
        Assert.Equal(true, stopped.GetTagItem("dhcpr.cancelled"));
    }

    [Fact]
    public async Task TracingDomainClientRecordsSuccessUpstreamMetrics()
    {
        var metrics = Substitute.For<IDnsMetrics>();
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

        metrics.Received(1).RecordUpstream(
            "udp",
            request,
            response,
            cancelled: false,
            error: false,
            Arg.Any<TimeSpan>());
    }

    [Fact]
    public async Task TracingDomainClientRecordsRaceCancelWithoutError()
    {
        var metrics = Substitute.For<IDnsMetrics>();
        var inner = Substitute.For<IDomainClient>();
        inner.SendAsync(Arg.Any<DomainMessage>(), Arg.Any<CancellationToken>())
            .Returns<DomainMessage>(_ => throw new OperationCanceledException());

        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        var request = DomainMessage.CreateRequest("example.com");
        var client = new TracingDomainClient(
            inner,
            new IPEndPoint(IPAddress.Parse("192.0.2.53"), 53),
            "udp",
            metrics);
        await Assert.ThrowsAsync<OperationCanceledException>(async () =>
            await client.SendAsync(request, cancelled.Token));

        metrics.Received(1).RecordUpstream(
            "udp",
            request,
            null,
            cancelled: true,
            error: false,
            Arg.Any<TimeSpan>());
    }

    [Fact]
    public async Task TracingDomainClientRecordsTimeoutAsError()
    {
        var metrics = Substitute.For<IDnsMetrics>();
        var inner = Substitute.For<IDomainClient>();
        inner.SendAsync(Arg.Any<DomainMessage>(), Arg.Any<CancellationToken>())
            .Returns<DomainMessage>(_ => throw new OperationCanceledException());

        var request = DomainMessage.CreateRequest("example.com", DomainRecordType.DNSKEY);
        var client = new TracingDomainClient(
            inner,
            new IPEndPoint(IPAddress.Parse("192.0.2.53"), 53),
            "tcp",
            metrics);
        await Assert.ThrowsAsync<OperationCanceledException>(async () =>
            await client.SendAsync(request, CancellationToken.None));

        metrics.Received(1).RecordUpstream(
            "tcp",
            request,
            null,
            cancelled: false,
            error: true,
            Arg.Any<TimeSpan>());
    }

    [Fact]
    public async Task TracingDomainClientRecordsExceptionAsError()
    {
        var metrics = Substitute.For<IDnsMetrics>();
        var inner = Substitute.For<IDomainClient>();
        inner.SendAsync(Arg.Any<DomainMessage>(), Arg.Any<CancellationToken>())
            .Returns<DomainMessage>(_ => throw new IOException("upstream reset"));

        var request = DomainMessage.CreateRequest("example.com");
        var client = new TracingDomainClient(
            inner,
            new IPEndPoint(IPAddress.Parse("192.0.2.53"), 53),
            "udp",
            metrics);
        await Assert.ThrowsAsync<IOException>(async () =>
            await client.SendAsync(request, CancellationToken.None));

        metrics.Received(1).RecordUpstream(
            "udp",
            request,
            null,
            cancelled: false,
            error: true,
            Arg.Any<TimeSpan>());
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
}
