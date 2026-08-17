using System.Net;
using System.Net.Sockets;

namespace Dhcpr.Dns.Core;

public sealed record ParsedDnsRoute(IPEndPoint[] Upstreams, IPNetwork[] Clients)
{
    public bool AllowsClient(IPAddress? client)
    {
        if (Clients.Length == 0)
            return true;
        if (client is null)
            return false;

        var address = client.IsIPv4MappedToIPv6 ? client.MapToIPv4() : client;
        foreach (var network in Clients)
        {
            if (network.Contains(address))
                return true;
        }

        return false;
    }

    internal static bool TryParseClientNetwork(string input, out IPNetwork network)
    {
        var trimmed = input.Trim();
        if (IPNetwork.TryParse(trimmed, out network))
            return true;

        if (IPAddress.TryParse(trimmed, out var host))
        {
            var prefix = host.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
            network = new IPNetwork(host, prefix);
            return true;
        }

        network = default;
        return false;
    }
}
