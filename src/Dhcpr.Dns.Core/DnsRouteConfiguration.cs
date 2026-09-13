using System.Diagnostics.CodeAnalysis;

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

    /// <summary>
    /// Strips a trailing FQDN dot, but keeps <c>.</c> as the catch-all route.
    /// </summary>
    public static bool TryNormalizeSuffix(string? suffix, [NotNullWhen(true)] out string? normalized)
    {
        var raw = suffix?.Trim() ?? "";
        if (raw is ".")
        {
            normalized = ".";
            return true;
        }

        normalized = raw.TrimEnd('.');
        if (string.IsNullOrWhiteSpace(normalized))
        {
            normalized = null;
            return false;
        }

        return true;
    }
}
