using Dhcpr.Dhcp.Core.Client;

namespace Dhcpr.Dhcp.Core.Pipeline;

public sealed record DhcpNetworkInformation(
    IPNetwork Network,
    int InterfaceIndex,
    string InterfaceName
);