using Dhcpr.Dhcp.Core.Client;

namespace Dhcpr.Dhcp.Core.Pipeline;

public sealed record DhcpNetworkInformation(
    DhcpNetwork Network,
    int InterfaceIndex,
    string InterfaceName
);