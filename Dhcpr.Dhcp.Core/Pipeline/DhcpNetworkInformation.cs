using System.Net;

namespace Dhcpr.Dhcp.Core.Pipeline;

public record DhcpNetworkInformation(
    IPAddress LocalAddress,
    IPAddress NetworkMask,
    IPAddress BroadcastAddress,
    int InterfaceIndex
);