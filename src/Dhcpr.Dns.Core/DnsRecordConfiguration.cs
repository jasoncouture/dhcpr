namespace Dhcpr.Dns.Core;

/// <summary>
/// One sparse overlay record from <c>DNS:Records</c>.
/// Empty <see cref="Clients"/> means any client may see the record.
/// </summary>
public sealed class DnsRecordConfiguration
{
    /// <summary>Owner name. Leftmost <c>*</c> is an RFC 4592 wildcard.</summary>
    public string Name { get; set; } = "";

    /// <summary>MVP types: A, AAAA, CNAME, NS.</summary>
    public string Type { get; set; } = "";

    /// <summary>TTL in seconds. Null uses 300.</summary>
    public int? Ttl { get; set; }

    /// <summary>IPv4, IPv6, or a domain name (CNAME/NS).</summary>
    public string Value { get; set; } = "";

    /// <summary>
    /// Client networks (CIDR, or a single IP) allowed to see this record.
    /// Empty = unrestricted.
    /// </summary>
    public string[] Clients { get; set; } = [];
}
