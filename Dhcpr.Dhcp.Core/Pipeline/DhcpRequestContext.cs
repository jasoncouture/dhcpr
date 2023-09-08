using Dhcpr.Dhcp.Core.Protocol;

namespace Dhcpr.Dhcp.Core.Pipeline;

public sealed class DhcpRequestContext
{
    public required DhcpNetworkInformation NetworkInformation { get; init; }
    public required DhcpMessage Message { get; init; }
    public bool Cancel { get; set; }
    public DhcpMessage? Response { get; set; }
}