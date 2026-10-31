using System.Buffers;
using System.Net;
using System.Net.Sockets;

using Dhcpr.Core;
using Dhcpr.Dns.Core.Protocol.Parser;

namespace Dhcpr.Dns.Core.Protocol.Processing;

public sealed class TcpDomainClient : IDomainClient
{
    private readonly ISocketFactory _socketFactory;
    private readonly IPEndPoint _target;

    public TcpDomainClient(ISocketFactory socketFactory, IPEndPoint target)
    {
        _socketFactory = socketFactory;
        _target = target;
    }

    public async ValueTask<DomainMessage> SendAsync(DomainMessage message, CancellationToken cancellationToken)
    {
        var tcpClient = await _socketFactory.GetTcpClientAsync(_target, cancellationToken);
        var buffer = ArrayPool<byte>.Shared.Rent(65535);
        try
        {
            var payloadLength = DomainMessageEncoder.Encode(buffer.AsSpan(2), message);
            BitConverter.TryWriteBytes(buffer.AsSpan(0, 2), ((ushort)payloadLength).ToNetworkByteOrder());
            await tcpClient.Client.SendAsync(buffer.AsMemory(0, payloadLength + 2), cancellationToken);

            await ReadExactAsync(tcpClient.Client, buffer.AsMemory(0, 2), cancellationToken);
            var responseLength = BitConverter.ToUInt16(buffer.AsSpan(0, 2)).ToHostByteOrder();
            if (responseLength == 0 || responseLength > buffer.Length)
                throw new InvalidOperationException($"Invalid DNS TCP response length: {responseLength}");

            await ReadExactAsync(tcpClient.Client, buffer.AsMemory(0, responseLength), cancellationToken);
            var response = DomainMessageEncoder.Decode(buffer.AsSpan(0, responseLength));
            if (response.Id != message.Id)
                throw new InvalidOperationException("DNS TCP response ID did not match the request.");
            return response;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
            tcpClient.Dispose();
        }
    }

    private static async Task ReadExactAsync(Socket socket, Memory<byte> buffer, CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var received = await socket.ReceiveAsync(buffer[offset..], cancellationToken);
            if (received == 0)
                throw new IOException("Remote DNS server closed the TCP connection.");
            offset += received;
        }
    }
}
