using System.Diagnostics.Metrics;

using Dhcpr.Core;

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
        Dictionary<string, object?> tags = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
        var result = await _inner.ProcessAsync(context, cancellationToken);
        // ReSharper disable once MethodSupportsCancellation - Intentional
        Task.Run(() =>
            {
                var count = context.DomainMessage.Questions.Length;
                if (count == 0) return;

                tags.Add("cache_hit", context.CacheHit);
                tags.Add("error", result is null);
                foreach (var question in context.DomainMessage.Questions)
                {
                    tags["query_type"] = question.Type.ToString("G");
                    tags["query_class"] = question.Class.ToString("G");
                    _queries.Add(1, tags.ToArray());
                }
            }
        ).IgnoreExceptionsAsync().Orphan();

        return result;
    }
}