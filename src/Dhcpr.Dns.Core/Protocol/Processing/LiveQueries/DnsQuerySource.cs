namespace Dhcpr.Dns.Core.Protocol.Processing;

/// <summary>
/// External ingress that produced a client query. Internal hops keep the
/// parent's value but are not shown in the live-query UI.
/// </summary>
public enum DnsQuerySource : byte
{
    Unknown = 0,
    Udp = 1,
    Tcp = 2,
    Dot = 3,
    Doh = 4
}

public static class DnsQuerySourceExtensions
{
    public static string ToLabel(this DnsQuerySource source) => source switch
    {
        DnsQuerySource.Udp => "UDP",
        DnsQuerySource.Tcp => "TCP",
        DnsQuerySource.Dot => "DoT",
        DnsQuerySource.Doh => "DoH",
        _ => "—"
    };

    public static string ToMetricLabel(this DnsQuerySource source)
        => source is DnsQuerySource.Unknown ? "unknown" : source.ToLabel();
}
