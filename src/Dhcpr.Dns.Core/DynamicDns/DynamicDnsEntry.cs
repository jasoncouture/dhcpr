namespace Dhcpr.Dns.Core.DynamicDns;

public sealed class DynamicDnsEntry
{
    public string? Ipv4 { get; set; }
    public string? Ipv6 { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}
