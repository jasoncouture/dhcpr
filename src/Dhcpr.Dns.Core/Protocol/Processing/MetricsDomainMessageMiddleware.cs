using System.Diagnostics.Metrics;

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
            description: "DNS queries received by the server");
    }

    public string Name => _inner.Name;
    public int Priority => _inner.Priority;

    public async ValueTask<DomainMessage?> ProcessAsync(
        DomainMessageContext context,
        CancellationToken cancellationToken)
    {
        context.CacheHit = false;
        var result = await _inner.ProcessAsync(context, cancellationToken);

        if (!context.IsInternal)
        {
            var count = context.DomainMessage.Questions.Length;
            if (count <= 0)
                count = 1;
            _queries.Add(count, new KeyValuePair<string, object?>("cache_hit", context.CacheHit));
        }

        return result;
    }
}
