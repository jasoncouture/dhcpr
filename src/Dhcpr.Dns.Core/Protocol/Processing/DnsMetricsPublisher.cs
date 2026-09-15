using System.Diagnostics;

using Dhcpr.Core.Metrics;

namespace Dhcpr.Dns.Core.Protocol.Processing;

public sealed class DnsMetricsPublisher : IDnsMetrics
{
    private readonly IPublishedCounter _queries;
    private readonly IPublishedHistogram _duration;
    private readonly IPublishedCounter _upstreamQueries;
    private readonly IPublishedHistogram _upstreamDuration;

    public DnsMetricsPublisher(IMetricPublisher metrics)
    {
        _queries = metrics.CreateCounter(
            DnsMetrics.MeterName,
            DnsMetrics.QueriesInstrumentName,
            unit: "{query}",
            description: "DNS queries answered by a middleware handler");
        _duration = metrics.CreateHistogram(
            DnsMetrics.MeterName,
            DnsMetrics.DurationInstrumentName,
            unit: "s",
            description: "DNS query processing duration",
            DnsMetrics.DurationSecondsBuckets);
        _upstreamQueries = metrics.CreateCounter(
            DnsMetrics.MeterName,
            DnsMetrics.UpstreamQueriesInstrumentName,
            unit: "{query}",
            description: "Outbound DNS nameserver queries");
        _upstreamDuration = metrics.CreateHistogram(
            DnsMetrics.MeterName,
            DnsMetrics.UpstreamDurationInstrumentName,
            unit: "s",
            description: "Outbound DNS nameserver query duration",
            DnsMetrics.DurationSecondsBuckets);
    }

    public void RecordQuery(DomainMessageContext context, DomainMessage response)
        => RecordQuery(
            context,
            response.Flags.ResponseCode.ToString("G"),
            response.Flags.ResponseCode is not DomainResponseCode.NoError);

    public void RecordQuery(DomainMessageContext context, string rcode, bool error)
    {
        if (context.IsInternal || context.BypassCache)
            return;

        if (context.DomainMessage.Questions.IsDefaultOrEmpty)
        {
            AddQuery(context, rcode, error, queryType: "none", queryClass: "none");
            return;
        }

        foreach (var question in context.DomainMessage.Questions)
            AddQuery(context, rcode, error, question.Type.ToString("G"), question.Class.ToString("G"));
    }

    public void RecordDuration(DomainMessageContext context, DomainMessage? response, TimeSpan elapsed)
    {
        if (context.IsInternal || context.BypassCache)
            return;

        if (response is null && context.AnsweredBy is not "UdpRateLimit")
            return;

        var question = context.DomainMessage.Questions.IsDefaultOrEmpty
            ? null
            : context.DomainMessage.Questions[0];
        var rcode = response is null
            ? DnsMetrics.DropRcode
            : response.Flags.ResponseCode.ToString("G");
        var error = response is null ||
                    response.Flags.ResponseCode is not DomainResponseCode.NoError;
        var tags = new TagList
        {
            { "cache_hit", context.CacheHit },
            { "error", error },
            { "rcode", rcode },
            { "query_type", question?.Type.ToString("G") ?? "none" },
            { "answered_by", context.AnsweredBy ?? "resolver" },
            { "source", context.Source.ToMetricLabel() }
        };
        _duration.Record(elapsed.TotalSeconds, in tags);
    }

    public void RecordUpstream(
        string transport,
        DomainMessage request,
        DomainMessage? response,
        bool cancelled,
        bool error,
        TimeSpan elapsed)
    {
        var question = request.Questions.IsDefaultOrEmpty ? null : request.Questions[0];
        var rcode = response is null
            ? DnsMetrics.NoneRcode
            : response.Flags.ResponseCode.ToString("G");
        var queryType = question?.Type.ToString("G") ?? DnsMetrics.NoneRcode;
        var tags = new TagList
        {
            { "network.transport", transport },
            { "error", error },
            { "cancelled", cancelled },
            { "rcode", rcode },
            { "query_type", queryType }
        };
        _upstreamDuration.Record(elapsed.TotalSeconds, in tags);
        _upstreamQueries.Add(1, in tags);
    }

    private void AddQuery(
        DomainMessageContext context,
        string rcode,
        bool error,
        string queryType,
        string queryClass)
    {
        var tags = new TagList
        {
            { "cache_hit", context.CacheHit },
            { "error", error },
            { "rcode", rcode },
            { "query_type", queryType },
            { "query_class", queryClass },
            { "answered_by", context.AnsweredBy ?? "resolver" },
            { "source", context.Source.ToMetricLabel() }
        };
        _queries.Add(1, in tags);
    }
}
