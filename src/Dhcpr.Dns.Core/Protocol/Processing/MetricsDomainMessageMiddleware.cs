using System.Diagnostics.Metrics;

using Dhcpr.Dns.Core.Protocol;

namespace Dhcpr.Dns.Core.Protocol.Processing;

public sealed class MetricsDomainMessageMiddleware : IDomainMessageMiddleware
{
    private readonly IDomainMessageMiddleware _inner;
    private readonly Counter<long> _queries;

    public MetricsDomainMessageMiddleware(IDomainMessageMiddleware inner, IMeterFactory meterFactory)
    {
        _inner = inner;
        var meter = meterFactory.Create(DnsMetrics.MeterName);
        _queries = meter.CreateCounter<long>(
            DnsMetrics.QueriesInstrumentName,
            unit: "{query}",
            description: "DNS queries answered by a middleware handler");
    }

    public string Name => _inner.Name;
    public int Priority => _inner.Priority;

    public async ValueTask<DomainMessage?> ProcessAsync(
        DomainMessageContext context,
        CancellationToken cancellationToken)
    {
        var result = await _inner.ProcessAsync(context, cancellationToken);

        // Null means this CoR handler declined — do not count pass-throughs as queries.
        if (result is null)
            return null;

        var error = result.Flags.ResponseCode is not DomainResponseCode.NoError;
        foreach (var question in context.DomainMessage.Questions)
        {
            _queries.Add(
                1,
                new KeyValuePair<string, object?>("cache_hit", context.CacheHit),
                new KeyValuePair<string, object?>("error", error),
                new KeyValuePair<string, object?>("query_type", question.Type.ToString("G")),
                new KeyValuePair<string, object?>("query_class", question.Class.ToString("G")));
        }

        return result;
    }
}
