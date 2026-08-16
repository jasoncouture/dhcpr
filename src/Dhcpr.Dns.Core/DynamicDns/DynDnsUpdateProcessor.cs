using System.Net;
using System.Net.Sockets;
using System.Text;

using Dhcpr.Dns.Core.Authoritative;
using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Zone;

namespace Dhcpr.Dns.Core.DynamicDns;

/// <summary>dyndns2-compatible update processing (auth + upsert status lines).</summary>
public static class DynDnsUpdateProcessor
{
    public static string Process(
        DynamicDnsStore store,
        AuthoritativeZoneStore zones,
        DynamicDnsConfiguration config,
        string? authorizationHeader,
        string? hostnameParam,
        string? myipParam,
        IPAddress? remoteIp,
        string? forwardedForFirstHop)
    {
        if (!config.Enabled)
            return "dnserr";

        if (!TryAuthenticate(authorizationHeader, config))
            return "badauth";

        if (string.IsNullOrWhiteSpace(hostnameParam))
            return "notfqdn";

        var hostnames = hostnameParam
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (hostnames.Length == 0)
            return "notfqdn";

        if (!TryResolveAddresses(myipParam, remoteIp, config.TrustForwardedFor, forwardedForFirstHop,
                out var ipv4, out var ipv6, out var displayIp))
            return "dnserr";

        var lines = new string[hostnames.Length];
        for (var i = 0; i < hostnames.Length; i++)
            lines[i] = UpdateOne(store, zones, hostnames[i], ipv4, ipv6, displayIp);

        return string.Join('\n', lines);
    }

    public static bool TryAuthenticate(string? authorizationHeader, DynamicDnsConfiguration config)
    {
        if (string.IsNullOrWhiteSpace(authorizationHeader) ||
            !authorizationHeader.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
            return false;

        try
        {
            var token = authorizationHeader["Basic ".Length..].Trim();
            var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(token));
            var sep = decoded.IndexOf(':');
            if (sep < 0)
                return false;

            var user = decoded[..sep];
            var pass = decoded[(sep + 1)..];
            return string.Equals(user, config.Username, StringComparison.Ordinal)
                   && string.Equals(pass, config.Password, StringComparison.Ordinal);
        }
        catch
        {
            return false;
        }
    }

    public static string BasicAuthorization(string username, string password)
        => $"Basic {Convert.ToBase64String(Encoding.UTF8.GetBytes($"{username}:{password}"))}";

    private static string UpdateOne(
        DynamicDnsStore store,
        AuthoritativeZoneStore zones,
        string hostname,
        IPAddress? ipv4,
        IPAddress? ipv6,
        string displayIp)
    {
        string normalized;
        try
        {
            normalized = RootZoneSnapshot.NormalizeOwner(hostname);
            if (normalized.Length == 0)
                return "notfqdn";
            _ = new DomainLabels(normalized);
        }
        catch
        {
            return "notfqdn";
        }

        if (zones.FindZone(normalized) is null)
            return "nohost";

        try
        {
            var result = store.Upsert(normalized, ipv4, ipv6);
            return result is DynamicDnsUpsertResult.Unchanged
                ? $"nochg {displayIp}"
                : $"good {displayIp}";
        }
        catch
        {
            return "dnserr";
        }
    }

    private static bool TryResolveAddresses(
        string? myipParam,
        IPAddress? remoteIp,
        bool trustForwardedFor,
        string? forwardedForFirstHop,
        out IPAddress? ipv4,
        out IPAddress? ipv6,
        out string displayIp)
    {
        ipv4 = null;
        ipv6 = null;
        displayIp = "";

        if (string.IsNullOrWhiteSpace(myipParam))
        {
            var remote = remoteIp;
            if (trustForwardedFor &&
                !string.IsNullOrWhiteSpace(forwardedForFirstHop) &&
                IPAddress.TryParse(forwardedForFirstHop, out var forwarded))
            {
                remote = forwarded;
            }

            if (remote is null)
                return false;

            if (remote.AddressFamily == AddressFamily.InterNetwork)
                ipv4 = remote;
            else if (remote.AddressFamily == AddressFamily.InterNetworkV6)
                ipv6 = remote;
            else
                return false;

            displayIp = remote.ToString();
            return true;
        }

        foreach (var part in myipParam.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (!IPAddress.TryParse(part, out var address))
                continue;

            if (address.AddressFamily == AddressFamily.InterNetwork)
                ipv4 = address;
            else if (address.AddressFamily == AddressFamily.InterNetworkV6)
                ipv6 = address;
        }

        if (ipv4 is null && ipv6 is null)
            return false;

        displayIp = ipv4?.ToString() ?? ipv6!.ToString();
        if (ipv4 is not null && ipv6 is not null)
            displayIp = $"{ipv4},{ipv6}";

        return true;
    }
}
