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
    /// The first bucket also has to sit under a cache hit. A 1 ms floor
    /// draws every faster query near 500 µs.
    /// </summary>
    public static readonly double[] DurationSecondsBuckets =
    [
        0.000025, 0.00005, 0.0001, 0.00025, 0.0005,
        0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10
    ];

    /// <summary>Synthetic rcode for a rate-limit ignore (no wire reply).</summary>
    public const string DropRcode = "Drop";

    /// <summary>Synthetic rcode when an upstream hop is cancelled or throws.</summary>
    public const string NoneRcode = "none";
}
