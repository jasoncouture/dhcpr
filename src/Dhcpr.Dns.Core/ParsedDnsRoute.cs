using System.Net;

namespace Dhcpr.Dns.Core;

public sealed record ParsedDnsRoute(IPEndPoint[] Upstreams, IPNetwork[] Clients)
{
    public bool AllowsClient(IPAddress? client)
        => new ClientAccessList(Clients).AllowsClient(client);

    internal static bool TryParseClientNetwork(string input, out IPNetwork network)
        => ClientAccessList.TryParseClientNetwork(input, out network);
}
