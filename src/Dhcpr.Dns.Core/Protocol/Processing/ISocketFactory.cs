using System.Net;
using System.Net.Sockets;

namespace Dhcpr.Dns.Core.Protocol.Processing;

public interface ISocketFactory
{
    UdpClient GetUdpClient(IPEndPoint? localEndPoint = null, bool exclusive = false);
    ValueTask<TcpClient> GetTcpClientAsync(IPEndPoint remoteEndPoint, CancellationToken cancellationToken);
}