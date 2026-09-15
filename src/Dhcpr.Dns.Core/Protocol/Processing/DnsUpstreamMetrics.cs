using System.Diagnostics.Metrics;

namespace Dhcpr.Dns.Core.Protocol.Processing;

/// <summary>
/// Process-bound upstream instruments. <see cref="TracingDomainClient"/> is
/// constructed per hop; creating the histogram there would leak meters.
/// </summary>
public sealed class DnsUpstreamMetrics
{
    private readonly Histogram<double> _duration;
    private readonly Counter<long> _queries;

    public DnsUpstreamMetrics(IMeterFactory meterFactory)
    {
        var meter = meterFactory.Create(DnsMetrics.MeterName);
        _duration = DnsMetrics.CreateDurationHistogram(
            meter,
            DnsMetrics.UpstreamDurationInstrumentName,
            "Outbound DNS nameserver query duration");
        _queries = meter.CreateCounter<long>(
            DnsMetrics.UpstreamQueriesInstrumentName,
            unit: "{query}",
            description: "Outbound DNS nameserver queries");
    }

    public void Record(
        string transport,
        DomainMessage request,
        DomainMessage? response,
        bool cancelled,
        bool error,
        TimeSpan elapsed)
        => DnsInstrumentation.RecordUpstream(
            _duration,
            _queries,
            transport,
            request,
            response,
            cancelled,
            error,
            elapsed);
}
