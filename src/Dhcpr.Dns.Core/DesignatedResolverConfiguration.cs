using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Sockets;

using Dhcpr.Core;

namespace Dhcpr.Dns.Core;

/// <summary>
/// One RFC 9462 designated resolver advertised as SVCB at <c>_dns.resolver.arpa</c>.
/// </summary>
public sealed class DesignatedResolverConfiguration
{
    /// <summary>SVCB SvcPriority. Must be greater than 0 (ServiceMode).</summary>
    public int Priority { get; set; } = 1;

    /// <summary>
    /// SVCB TargetName. Must not be the root or <c>resolver.arpa</c>.
    /// </summary>
    public string Target { get; set; } = "";

    public string[] Alpn { get; set; } = [];

    /// <summary>Optional SvcParam port. Omit to use the ALPN default.</summary>
    public int? Port { get; set; }

    /// <summary>RFC 9461 <c>dohpath</c> URI template. Must start with <c>/</c> when set.</summary>
    public string? DohPath { get; set; }

    public string[] Ipv4Hint { get; set; } = [];
    public string[] Ipv6Hint { get; set; } = [];

    public bool TryValidate(int index, [NotNullWhen(false)] out string? error)
    {
        if (Priority is < 1 or > ushort.MaxValue)
        {
            error = $"DNS:DesignatedResolvers[{index}].Priority must be 1–65535 (ServiceMode)";
            return false;
        }

        var target = Target?.Trim().TrimEnd('.');
        if (string.IsNullOrWhiteSpace(target) || !target.IsValidDomainName())
        {
            error = $"DNS:DesignatedResolvers[{index}].Target is not a valid hostname";
            return false;
        }

        if (target.Equals("resolver.arpa", StringComparison.OrdinalIgnoreCase) ||
            target.EndsWith(".resolver.arpa", StringComparison.OrdinalIgnoreCase))
        {
            error = $"DNS:DesignatedResolvers[{index}].Target must not be resolver.arpa";
            return false;
        }

        Target = target;

        if (Port is < 1 or > ushort.MaxValue)
        {
            error = $"DNS:DesignatedResolvers[{index}].Port must be 1–65535";
            return false;
        }

        Alpn ??= [];
        for (var i = 0; i < Alpn.Length; i++)
        {
            var id = Alpn[i]?.Trim();
            if (string.IsNullOrEmpty(id) || id.Length > 255)
            {
                error = $"DNS:DesignatedResolvers[{index}].Alpn[{i}] is empty or longer than 255 characters";
                return false;
            }

            Alpn[i] = id;
        }

        if (!string.IsNullOrEmpty(DohPath) && !DohPath.StartsWith('/'))
        {
            error = $"DNS:DesignatedResolvers[{index}].DohPath must start with /";
            return false;
        }

        if (!string.IsNullOrEmpty(DohPath) && Alpn.Length == 0)
        {
            error = $"DNS:DesignatedResolvers[{index}].Alpn is required when DohPath is set";
            return false;
        }

        Ipv4Hint ??= [];
        for (var i = 0; i < Ipv4Hint.Length; i++)
        {
            if (!IPAddress.TryParse(Ipv4Hint[i], out var address) ||
                address.AddressFamily != AddressFamily.InterNetwork)
            {
                error = $"DNS:DesignatedResolvers[{index}].Ipv4Hint[{i}] is not an IPv4 address";
                return false;
            }
        }

        Ipv6Hint ??= [];
        for (var i = 0; i < Ipv6Hint.Length; i++)
        {
            if (!IPAddress.TryParse(Ipv6Hint[i], out var address) ||
                address.AddressFamily != AddressFamily.InterNetworkV6)
            {
                error = $"DNS:DesignatedResolvers[{index}].Ipv6Hint[{i}] is not an IPv6 address";
                return false;
            }
        }

        error = null;
        return true;
    }
}
