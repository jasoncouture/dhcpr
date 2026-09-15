using System.Diagnostics;
using System.Net;

using Dhcpr.Core.Metrics;
using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;

using NSubstitute;

namespace Dhcpr.Dns.Core.UnitTests;

public class DnsMetricsPublisherTests
{
    [Fact]
    public void RecordQuerySkipsInternalAndBypass()
    {
        var fixtures = Create();
        var request = DomainMessage.CreateRequest("example.com");
        var response = DomainMessage.CreateResponse(request);

        fixtures.Metrics.RecordQuery(Context(request, isInternal: true), response);
        fixtures.Metrics.RecordQuery(Context(request, bypassCache: true), response);

        Assert.Empty(fixtures.Queries.Adds);
    }

    [Fact]
    public void RecordQueryTagsRateLimitRefused()
    {
        var fixtures = Create();
        var request = DomainMessage.CreateRequest("cisco.com", DomainRecordType.TXT);
        var response = DomainMessage.CreateResponse(request, responseCode: DomainResponseCode.Refused);
        var context = Context(request, answeredBy: "UdpRateLimit", source: DnsQuerySource.Udp);

        fixtures.Metrics.RecordQuery(context, response);

        var tags = Assert.Single(fixtures.Queries.Adds).Tags;
        Assert.Equal(nameof(DomainResponseCode.Refused), Tag(tags, "rcode"));
        Assert.Equal("UdpRateLimit", Tag(tags, "answered_by"));
        Assert.Equal("UDP", Tag(tags, "source"));
    }

    [Fact]
    public void RecordQueryTagsRateLimitDrop()
    {
        var fixtures = Create();
        var request = DomainMessage.CreateRequest("cisco.com", DomainRecordType.TXT);

        fixtures.Metrics.RecordQuery(Context(request, answeredBy: "UdpRateLimit"), DnsMetrics.DropRcode, error: true);

        Assert.Equal(DnsMetrics.DropRcode, Tag(Assert.Single(fixtures.Queries.Adds).Tags, "rcode"));
    }

    [Fact]
    public void RecordDurationSkipsInternalAndBypass()
    {
        var fixtures = Create();
        var request = DomainMessage.CreateRequest("example.com");
        var response = DomainMessage.CreateResponse(request);

        fixtures.Metrics.RecordDuration(Context(request, isInternal: true), response, TimeSpan.FromMilliseconds(5));
        fixtures.Metrics.RecordDuration(Context(request, bypassCache: true), response, TimeSpan.FromMilliseconds(5));

        Assert.Empty(fixtures.Duration.Records);
    }

    [Fact]
    public void RecordDurationRecordsClientAnswers()
    {
        var fixtures = Create();
        var request = DomainMessage.CreateRequest("example.com");
        var response = DomainMessage.CreateResponse(request);

        fixtures.Metrics.RecordDuration(Context(request), response, TimeSpan.FromMilliseconds(25));

        Assert.Equal(0.025, Assert.Single(fixtures.Duration.Records).Value);
    }

    [Fact]
    public void RecordDurationTagsSource()
    {
        var fixtures = Create();
        var request = DomainMessage.CreateRequest("example.com");
        var response = DomainMessage.CreateResponse(request);

        fixtures.Metrics.RecordDuration(Context(request, source: DnsQuerySource.Dot), response, TimeSpan.FromMilliseconds(25));

        Assert.Equal("DoT", Tag(Assert.Single(fixtures.Duration.Records).Tags, "source"));
    }

    [Fact]
    public void RecordUpstreamTagsSuccess()
    {
        var fixtures = Create();
        var request = DomainMessage.CreateRequest("example.com", DomainRecordType.NS);
        var response = DomainMessage.CreateResponse(request, responseCode: DomainResponseCode.NoError);

        fixtures.Metrics.RecordUpstream(
            "udp",
            request,
            response,
            cancelled: false,
            error: false,
            TimeSpan.FromMilliseconds(10));

        var tags = Assert.Single(fixtures.UpstreamQueries.Adds).Tags;
        Assert.Equal("udp", Tag(tags, "network.transport"));
        Assert.Equal(false, Tag(tags, "error"));
        Assert.Equal(false, Tag(tags, "cancelled"));
        Assert.Equal(nameof(DomainResponseCode.NoError), Tag(tags, "rcode"));
        Assert.Equal(nameof(DomainRecordType.NS), Tag(tags, "query_type"));
        Assert.Equal(0.01, Assert.Single(fixtures.UpstreamDuration.Records).Value);
    }

    private static Fixtures Create()
    {
        var queries = new RecordingCounter();
        var duration = new RecordingHistogram();
        var upstreamQueries = new RecordingCounter();
        var upstreamDuration = new RecordingHistogram();
        var publisher = Substitute.For<IMetricPublisher>();
        publisher.CreateCounter(Arg.Any<string>(), DnsMetrics.QueriesInstrumentName, Arg.Any<string?>(), Arg.Any<string?>())
            .Returns(queries);
        publisher.CreateCounter(Arg.Any<string>(), DnsMetrics.UpstreamQueriesInstrumentName, Arg.Any<string?>(), Arg.Any<string?>())
            .Returns(upstreamQueries);
        publisher.CreateHistogram(
                Arg.Any<string>(),
                DnsMetrics.DurationInstrumentName,
                Arg.Any<string?>(),
                Arg.Any<string?>(),
                Arg.Any<double[]?>())
            .Returns(duration);
        publisher.CreateHistogram(
                Arg.Any<string>(),
                DnsMetrics.UpstreamDurationInstrumentName,
                Arg.Any<string?>(),
                Arg.Any<string?>(),
                Arg.Any<double[]?>())
            .Returns(upstreamDuration);
        return new Fixtures(
            new DnsMetricsPublisher(publisher),
            queries,
            duration,
            upstreamQueries,
            upstreamDuration);
    }

    private static DomainMessageContext Context(
        DomainMessage request,
        bool isInternal = false,
        bool bypassCache = false,
        string? answeredBy = null,
        DnsQuerySource source = DnsQuerySource.Unknown)
    {
        var context = new DomainMessageContext(
            new IPEndPoint(IPAddress.Loopback, 53000),
            new IPEndPoint(IPAddress.Loopback, 53),
            request)
        {
            IsInternal = isInternal,
            BypassCache = bypassCache,
            Source = source
        };
        if (answeredBy is not null)
            context.AnsweredBy = answeredBy;
        return context;
    }

    private static object? Tag(IReadOnlyList<KeyValuePair<string, object?>> tags, string key)
    {
        foreach (var tag in tags)
        {
            if (tag.Key == key)
                return tag.Value;
        }

        return null;
    }

    private sealed record Fixtures(
        IDnsMetrics Metrics,
        RecordingCounter Queries,
        RecordingHistogram Duration,
        RecordingCounter UpstreamQueries,
        RecordingHistogram UpstreamDuration);

    private sealed class RecordingCounter : IPublishedCounter
    {
        public List<(long Value, IReadOnlyList<KeyValuePair<string, object?>> Tags)> Adds { get; } = [];

        public void Add(long value, in TagList tags)
            => Adds.Add((value, Copy(tags)));
    }

    private sealed class RecordingHistogram : IPublishedHistogram
    {
        public List<(double Value, IReadOnlyList<KeyValuePair<string, object?>> Tags)> Records { get; } = [];

        public void Record(double value, in TagList tags)
            => Records.Add((value, Copy(tags)));
    }

    private static IReadOnlyList<KeyValuePair<string, object?>> Copy(in TagList tags)
    {
        var copy = new KeyValuePair<string, object?>[tags.Count];
        var i = 0;
        foreach (var tag in tags)
            copy[i++] = tag;
        return copy;
    }
}
