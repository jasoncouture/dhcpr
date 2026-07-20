using System.Net.Sockets;

using Dhcpr.Dhcp.Core.Pipeline;

namespace Dhcpr.Dhcp.Core;

public sealed record QueuedDhcpMessage(UdpClient Socket, DhcpRequestContext Context);