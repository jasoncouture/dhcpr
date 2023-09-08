using System.Net.Sockets;

using Dhcpr.Dhcp.Core.Pipeline;

namespace Dhcpr.Dhcp.Core;

public record QueuedDhcpMessage(UdpClient Socket, DhcpRequestContext Context);