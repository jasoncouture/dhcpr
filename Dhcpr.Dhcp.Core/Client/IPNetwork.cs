using System.Net;

using Dhcpr.Core;

namespace Dhcpr.Dhcp.Core.Client;

public sealed record IPNetwork(IPAddress Address, IPAddress NetworkMask, IPAddress BroadcastAddress)
{
    public bool Contains(IPAddress address) =>
        address.IsInNetwork(Address, NetworkMask);
}