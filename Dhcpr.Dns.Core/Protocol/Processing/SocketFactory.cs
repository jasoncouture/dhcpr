using System.Net;
using System.Net.Sockets;

namespace Dhcpr.Dns.Core.Protocol.Processing;

public sealed class SocketFactory : ISocketFactory
{
    public UdpClient GetUdpClient(IPEndPoint? localEndPoint, bool exclusive = false)
    {
        localEndPoint ??= new IPEndPoint(IPAddress.Any, 0);
        var client = new UdpClient(localEndPoint.AddressFamily);
        //client.ExclusiveAddressUse = !exclusive;
        // client.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        client.Client.Bind(localEndPoint);
        return client;
    }

    public async ValueTask<TcpClient> GetTcpClientAsync(IPEndPoint remoteEndPoint, CancellationToken cancellationToken)
    {
        var client = new TcpClient();
        client.NoDelay = true;
        await client.ConnectAsync(remoteEndPoint, cancellationToken);
        return client;
    }
}