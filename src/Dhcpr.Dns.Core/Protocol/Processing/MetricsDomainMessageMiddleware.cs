using System.Diagnostics.Metrics;

namespace Dhcpr.Dns.Core.Protocol.Processing;

public sealed class MetricsDomainMessageMiddleware : IDomainMessageMiddleware
{
    private readonly ICacheState _cacheState;
    private readonly Counter<long> _queries;

    public MetricsDomainMessageMiddleware(IMeterFactory meterFactory, ICacheState cacheState)
    {
        _cacheState = cacheState;
        var meter = meterFactory.Create(DnsMetrics.MeterName);
        _queries = meter.CreateCounter<long>(
            DnsMetrics.QueriesInstrumentName,
            unit: "{query}",
            description: "DNS queries received by the server");
    }

    public string Name => "DNS Metrics";
    public int Priority => int.MinValue;

    public ValueTask<DomainMessage?> ProcessAsync(DomainMessageContext context, CancellationToken cancellationToken)
    {
        var count = context.DomainMessage.Questions.Length;
        if (count > 0)
            _queries.Add(count, new KeyValuePair<string, object?>("cache_hit", _cacheState.CacheHit));
        else
            _queries.Add(1, new KeyValuePair<string, object?>("cache_hit", _cacheState.CacheHit));

        return default;
    }
}