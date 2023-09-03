using System.Net;
using System.Net.Sockets;

using Dhcpr.Dhcp.Core.Protocol;

namespace Dhcpr.Dhcp.Core.Pipeline;

public interface IDhcpRequestHandler
{
    int Order => 0;
    ValueTask HandleDhcpRequest(DhcpRequestContext context, CancellationToken cancellationToken);
}

public class DhcpRequestContext
{
    public required DhcpNetworkInformation NetworkInformation { get; init; }
    public required DhcpMessage Message { get; init; }
    public DhcpMessage? Response { get; init; }
}

public record DhcpNetworkInformation(
    IPAddress LocalAddress,
    IPAddress NetworkMask,
    IPAddress BroadcastAddress,
    int InterfaceIndex
);