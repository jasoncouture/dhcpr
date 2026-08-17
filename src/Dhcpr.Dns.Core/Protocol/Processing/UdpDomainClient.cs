using System.Buffers;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Sockets;

using Dhcpr.Dns.Core.Protocol.Parser;

namespace Dhcpr.Dns.Core.Protocol.Processing;

[SuppressMessage("ReSharper", "SuggestBaseTypeForParameter",
    Justification = "Explicit types are desired, as only IP is supported.")]
public sealed class UdpDomainClient : IDomainClient
{
    private readonly UdpClient _udpClient;
    private readonly IPEndPoint _target;

    public UdpDomainClient(UdpClient udpClient, IPEndPoint target)
    {
        _udpClient = udpClient;
        _target = target;
    }

    public void Dispose() => _udpClient.Dispose();


    public async ValueTask<DomainMessage> SendAsync(DomainMessage message,
        CancellationToken cancellationToken)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(16384);
        try
        {
            int length = DomainMessageEncoder.Encode(((Memory<byte>)buffer).Span, message);

            await _udpClient.Client.SendToAsync(((Memory<byte>)buffer)[..length], _target, cancellationToken);
            return await ReceiveAndDecodeAsync(_udpClient.Client, _target, (Memory<byte>)buffer, message.Id, cancellationToken);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static async ValueTask<DomainMessage> ReceiveAndDecodeAsync(Socket socket,
        IPEndPoint target,
        Memory<byte> buffer,
        ushort messageId,
        CancellationToken cancellationToken)
    {
        // Clone so ReceiveFromAsync cannot mutate the caller's target endpoint.
        var receiveFrom = new IPEndPoint(target.Address, target.Port);
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var socketResult = await socket.ReceiveFromAsync(buffer, receiveFrom, cancellationToken);
            if (!IsExpectedSource(socketResult.RemoteEndPoint, target))
                continue;

            var result = DomainMessageEncoder.Decode(buffer.Span[..socketResult.ReceivedBytes]);

            if (result.Id != messageId) // ID did not match, try again.
                continue;

            return result;
        }
    }

    private static bool IsExpectedSource(EndPoint remote, IPEndPoint target)
        => remote is IPEndPoint from &&
           from.Port == target.Port &&
           from.Address.Equals(target.Address);
}