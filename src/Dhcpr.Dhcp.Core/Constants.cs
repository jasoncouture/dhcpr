using System.Net;

namespace Dhcpr.Dhcp.Core;

static class Constants
{
    public static readonly IPEndPoint ClientDefaultEndpoint = new(IPAddress.Broadcast, DhcpClientPort);
    public static readonly IPEndPoint ServerEndpoint = new(IPAddress.Any, DhcpServerPort);

    public const int DhcpServerPort = 67;
    public const int DhcpClientPort = 68;
}