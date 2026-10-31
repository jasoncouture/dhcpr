namespace Dhcpr.Dns.Core.Protocol.Processing.Middleware;

public sealed class MetricsDomainMessageMiddleware : IDomainMessageMiddleware
{
    private readonly IDomainMessageMiddleware _inner;
    private readonly IDnsMetrics _metrics;

    public MetricsDomainMessageMiddleware(IDomainMessageMiddleware inner, IDnsMetrics metrics)
    {
        _inner = inner;
        _metrics = metrics;
    }

    public string Name => _inner.Name;
    public int Priority => _inner.Priority;

    public async ValueTask<DomainMessage> ProcessAsync(
        DomainMessageContext context,
        CancellationToken cancellationToken)
    {
        var result = await _inner.ProcessAsync(context, cancellationToken);
        if (context.Cancel)
            _metrics.RecordQuery(context, DnsMetrics.DropRcode, error: true);
        else
            _metrics.RecordQuery(context, result);
        return result;
    }
}
