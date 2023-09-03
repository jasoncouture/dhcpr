using Dhcpr.Dhcp.Core.Protocol;

namespace Dhcpr.Dhcp.Core.Pipeline;

public class DhcpRequestContext
{
    public required DhcpNetworkInformation NetworkInformation { get; init; }
    public required DhcpMessage Message { get; init; }
    public DhcpMessage? Response { get; init; }
}