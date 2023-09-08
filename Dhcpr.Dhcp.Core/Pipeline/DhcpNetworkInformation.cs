using Dhcpr.Dhcp.Core.Client;

namespace Dhcpr.Dhcp.Core.Pipeline;

public record DhcpNetworkInformation(
    IPNetwork Network,
    int InterfaceIndex,
    string InterfaceName
);