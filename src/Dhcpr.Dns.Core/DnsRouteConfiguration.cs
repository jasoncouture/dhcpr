namespace Dhcpr.Dns.Core;

/// <summary>
/// Conditional forwarder for one domain suffix.
/// Empty <see cref="Clients"/> means any client may use the route.
/// </summary>
public sealed class DnsRouteConfiguration
{
    /// <summary>Upstream nameserver endpoints (<c>host:port</c>, port defaults to 53).</summary>
    public string[] Upstreams { get; set; } = [];

    /// <summary>
    /// Client networks (CIDR, or a single IP) allowed to use this route.
    /// Empty = unrestricted.
    /// </summary>
    public string[] Clients { get; set; } = [];
}
