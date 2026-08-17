using System.Net;
using System.Net.Sockets;

namespace Dhcpr.Dns.Core.Protocol.Processing;

public interface ISocketFactory
{
    /// <summary>
    /// Creates a UDP client bound to <paramref name="localEndPoint"/> (or an ephemeral any-address port when omitted).
    /// </summary>
    UdpClient GetUdpClient(IPEndPoint? localEndPoint = null, bool exclusive = false);

    /// <summary>
    /// Connects a TCP client to <paramref name="remoteEndPoint"/>.
    /// </summary>
    ValueTask<TcpClient> GetTcpClientAsync(IPEndPoint remoteEndPoint, CancellationToken cancellationToken);
}