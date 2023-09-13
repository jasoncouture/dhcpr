using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Sockets;

using Dhcpr.Dns.Core.Protocol.Parser;

namespace Dhcpr.Dns.Core.Protocol.Processing;

[SuppressMessage("ReSharper", "SuggestBaseTypeForParameter",
    Justification = "Explicit types are desired, as only IP is supported.")]
public sealed class DomainClient : IDomainClient
{
    private readonly ISocketFactory _socketFactory;

    public DomainClient(ISocketFactory socketFactory)
    {
        _socketFactory = socketFactory;
    }

    private static readonly IPEndPoint UdpBindEndPoint = new(IPAddress.Any, 0);

    private async ValueTask<DomainMessage> SendTcpInternalAsync(byte[] buffer, IPEndPoint target, DomainMessage message,
        CancellationToken cancellationToken)
    {
        using var client = await
            _socketFactory.GetTcpClientAsync(target, cancellationToken);
        int length = EncodeMessage(buffer, message);

        await client.Client.SendAsync(new ArraySegment<byte>(buffer, 0, length).AsMemory(), cancellationToken);
        return await ReceiveAndDecodeAsync(client.Client, target, buffer, message.Id,
            static async (socket, _, payload, ct) => await socket.ReceiveAsync(payload, ct), cancellationToken);
    }


    public async ValueTask<DomainMessage> SendAsync(IPEndPoint target, DomainMessage message, bool tcp,
        CancellationToken cancellationToken)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(16384);
        try
        {
            if (tcp)
            {
                return await SendTcpInternalAsync(buffer, target, message, cancellationToken);
            }

            return await SendUdpInternalAsync(buffer, target, message, cancellationToken);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private async ValueTask<DomainMessage> SendUdpInternalAsync(
        Memory<byte> buffer,
        IPEndPoint target,
        DomainMessage message,
        CancellationToken cancellationToken
    )
    {
        using var client =
            _socketFactory.GetUdpClient(UdpBindEndPoint);
        int length = EncodeMessage(buffer, message);

        await client.Client.SendToAsync(buffer[..length], target, cancellationToken);
        return await ReceiveAndDecodeAsync(client.Client, target, buffer, message.Id,
            static async (socket, endPoint, payload, tc) => await socket.ReceiveFromAsync(payload, endPoint, tc),
            cancellationToken);
    }

    private static int EncodeMessage(Memory<byte> data, DomainMessage message) =>
        DomainMessageEncoder.Encode(data.Span, message);

    private static async ValueTask<DomainMessage> ReceiveAndDecodeAsync(Socket socket,
        IPEndPoint target,
        Memory<byte> buffer,
        ushort messageId,
        Func<Socket, IPEndPoint, Memory<byte>, CancellationToken, ValueTask> receiveDataMethod,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            await receiveDataMethod.Invoke(socket, target, buffer, cancellationToken);
            var result = DecodeMessage(buffer, messageId);
            if (result is null) // ID did not match, try again.
                continue;
            return result;
        }
    }

    private static DomainMessage? DecodeMessage(Memory<byte> rentedArray, ushort id)
    {
        var result = DomainMessageEncoder.Decode(rentedArray.Span);
        if (result.Id != id) return null;
        return result;
    }
}