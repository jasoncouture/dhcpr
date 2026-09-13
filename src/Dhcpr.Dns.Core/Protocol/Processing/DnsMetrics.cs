using System.Diagnostics.Metrics;

namespace Dhcpr.Dns.Core.Protocol.Processing;

public static class DnsMetrics
{
    public const string MeterName = "Dhcpr.Dns";
    public const string QueriesInstrumentName = "dns.queries";
    public const string DurationInstrumentName = "dns.query.duration";

    /// <summary>
    /// Increments <c>dns.queries</c> with the same tags as
    /// <see cref="MetricsDomainMessageMiddleware"/>. Used for answers that
    /// never enter the decorate chain (UDP rate-limit REFUSED).
    /// </summary>
    public static void RecordQueries(
        Counter<long> queries,
        DomainMessageContext context,
        DomainMessage response)
    {
        if (context.BypassCache)
            return;

        var error = response.Flags.ResponseCode is not DomainResponseCode.NoError;
        foreach (var question in context.DomainMessage.Questions)
        {
            queries.Add(
                1,
                new KeyValuePair<string, object?>("cache_hit", context.CacheHit),
                new KeyValuePair<string, object?>("error", error),
                new KeyValuePair<string, object?>("rcode", response.Flags.ResponseCode.ToString("G")),
                new KeyValuePair<string, object?>("query_type", question.Type.ToString("G")),
                new KeyValuePair<string, object?>("query_class", question.Class.ToString("G")),
                new KeyValuePair<string, object?>("answered_by", context.AnsweredBy ?? "resolver"));
        }
    }
}
