namespace Dhcpr.Dns.Core.Protocol.Processing;

/// <summary>
/// RFC 6303 / RFC 7793 locally served reverse zones. Resolving these on the
/// public Internet leaks RFC1918/link-local names and often DNSSEC-SERVFAILs.
/// </summary>
public static class Rfc6303EmptyZones
{
    public static IReadOnlyList<string> Zones { get; } = BuildZones();

    public static bool TryMatch(DomainLabels name, out string zone, out bool isApex)
    {
        var qname = name.ToString();
        foreach (var candidate in Zones)
        {
            if (qname.Equals(candidate, StringComparison.OrdinalIgnoreCase))
            {
                zone = candidate;
                isApex = true;
                return true;
            }

            if (qname.Length > candidate.Length + 1 &&
                qname.EndsWith($".{candidate}", StringComparison.OrdinalIgnoreCase))
            {
                zone = candidate;
                isApex = false;
                return true;
            }
        }

        zone = "";
        isApex = false;
        return false;
    }

    private static string[] BuildZones()
    {
        var zones = new List<string>
        {
            "0.in-addr.arpa",
            "10.in-addr.arpa",
            "127.in-addr.arpa",
            "168.192.in-addr.arpa",
            "254.169.in-addr.arpa",
            "255.in-addr.arpa",
            "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
            "8.e.f.ip6.arpa",
            "9.e.f.ip6.arpa",
            "a.e.f.ip6.arpa",
            "b.e.f.ip6.arpa",
            "d.f.ip6.arpa",
        };
        for (var octet = 16; octet <= 31; octet++)
            zones.Add($"{octet}.172.in-addr.arpa");
        // RFC 7793: Shared Address Space (100.64.0.0/10)
        for (var octet = 64; octet <= 127; octet++)
            zones.Add($"{octet}.100.in-addr.arpa");

        return zones
            .OrderByDescending(static z => z.Count(static c => c == '.'))
            .ThenBy(static z => z, StringComparer.Ordinal)
            .ToArray();
    }
}
