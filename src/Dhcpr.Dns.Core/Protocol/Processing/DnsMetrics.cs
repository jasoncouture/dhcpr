using System.Diagnostics.Metrics;

namespace Dhcpr.Dns.Core.Protocol.Processing;

public static class DnsMetrics
{
    public const string MeterName = "Dhcpr.Dns";
    public const string QueriesInstrumentName = "dns.queries";
    public const string DurationInstrumentName = "dns.query.duration";
    public const string UpstreamQueriesInstrumentName = "dns.upstream.queries";
    public const string UpstreamDurationInstrumentName = "dns.upstream.duration";

    /// <summary>
    /// Second-scale buckets. The SDK default (5, 10, 25, …) is meant for
    /// milliseconds — with unit <c>s</c> every real miss lands in <c>le="5"</c>
    /// and <c>histogram_quantile</c> interpolates a multi-second p50.
    /// </summary>
    public static readonly double[] DurationSecondsBuckets =
    [
        0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10
    ];

    public static Histogram<double> CreateDurationHistogram(
        Meter meter,
        string name,
        string description)
        => meter.CreateHistogram<double>(
            name,
            unit: "s",
            description,
            advice: new InstrumentAdvice<double>
            {
                HistogramBucketBoundaries = DurationSecondsBuckets
            });

    /// <summary>Synthetic rcode for a rate-limit ignore (no wire reply).</summary>
    public const string DropRcode = "Drop";

    /// <summary>Synthetic rcode when an upstream hop is cancelled or throws.</summary>
    public const string NoneRcode = "none";

    /// <summary>
    /// Increments <c>dns.queries</c> with the same tags as
    /// <see cref="MetricsDomainMessageMiddleware"/>. Used for answers that
    /// never enter the decorate chain (rate-limit REFUSED / Drop).
    /// </summary>
    public static void RecordQueries(
        Counter<long> queries,
        DomainMessageContext context,
        DomainMessage response)
        => RecordQueries(
            queries,
            context,
            response.Flags.ResponseCode.ToString("G"),
            response.Flags.ResponseCode is not DomainResponseCode.NoError);

    public static void RecordQueries(
        Counter<long> queries,
        DomainMessageContext context,
        string rcode,
        bool error)
    {
        if (context.IsInternal || context.BypassCache)
            return;

        if (context.DomainMessage.Questions.IsDefaultOrEmpty)
        {
            queries.Add(1, Tags(context, rcode, error, queryType: "none", queryClass: "none"));
            return;
        }

        foreach (var question in context.DomainMessage.Questions)
        {
            queries.Add(1, Tags(context, rcode, error, question.Type.ToString("G"), question.Class.ToString("G")));
        }
    }

    private static KeyValuePair<string, object?>[] Tags(
        DomainMessageContext context,
        string rcode,
        bool error,
        string queryType,
        string queryClass)
        =>
        [
            new("cache_hit", context.CacheHit),
            new("error", error),
            new("rcode", rcode),
            new("query_type", queryType),
            new("query_class", queryClass),
            new("answered_by", context.AnsweredBy ?? "resolver"),
            new("source", context.Source.ToMetricLabel())
        ];
}
