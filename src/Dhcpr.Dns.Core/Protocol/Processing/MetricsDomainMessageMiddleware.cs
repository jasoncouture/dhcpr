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

        DnsMetrics.RecordQueries(_queries, context, result);
        return result;
    }
}
