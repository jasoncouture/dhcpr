using System.Diagnostics.Metrics;
using System.Net;

namespace Dhcpr.Dns.Core.Protocol.Processing;

public sealed class MetricsDomainMessageMiddleware : IDomainMessageMiddleware
{
    private static readonly IPAddress InternalAddress = IPAddress.Any;

    private readonly Counter<long> _queries;

    public MetricsDomainMessageMiddleware(IMeterFactory meterFactory)
    {
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
        if (!IsInternalRequest(context))
        {
            var count = context.DomainMessage.Questions.Length;
            if (count > 0)
                _queries.Add(count);
            else
                _queries.Add(1);
        }

        return default;
    }

    private static bool IsInternalRequest(DomainMessageContext context) =>
        context.ClientEndPoint is { Port: 53 } endpoint &&
        endpoint.Address.Equals(InternalAddress);
}
