using System.Buffers;
using System.Collections.Immutable;
using System.Net;
using System.Net.Sockets;

using Dhcpr.Core;
using Dhcpr.Core.Linq;
using Dhcpr.Core.Queue;
using Dhcpr.Dns.Core.Protocol.Parser;

using DNS.Protocol;

namespace Dhcpr.Dns.Core.Protocol.Processing;

public sealed class DomainMessageContextMessageProcessor : IQueueMessageProcessor<DnsPacketReceivedMessage>, IDisposable
{
    private readonly PooledList<IDomainMessageMiddleware> _middlewareChain;

    public DomainMessageContextMessageProcessor(IEnumerable<IDomainMessageMiddleware> middlewareChain)
    {
        _middlewareChain = middlewareChain.OrderBy(i => i.Priority).ToPooledList();
    }

    public async Task ProcessMessageAsync(DnsPacketReceivedMessage message, CancellationToken cancellationToken)
    {
        DomainMessage? response = null;
        foreach (var middleware in _middlewareChain)
        {
            response = await middleware.ProcessAsync(message.Context, cancellationToken);
            if (message.Context.Cancel) // This is intended for things that want to ignore the request.
                break;
            if (response is not null) // This is intended for things to say "I don't handle this, try next"
                break;
        }

        // This is a directive to ignore the message.
        // The middleware may have responded to it, or may be blocking this client.
        if (response is null)
            return;

        if (response.Id != message.Context.DomainMessage.Id)
        {
            response = response with { Id = message.Context.DomainMessage.Id };
        }


        await SendResponseAsync(message, response, cancellationToken);
    }

    private static async Task SendResponseAsync(
        DnsPacketReceivedMessage message,
        DomainMessage response,
        CancellationToken cancellationToken
    )
    {
        var buffer = ArrayPool<byte>.Shared.Rent(response.Size);
        try
        {
            var byteCount = TruncateAndEncodeMessage(
                response,
                message is UdpDnsPacketReceivedMessage ? 1024 : int.MaxValue,
                buffer
            );
            var segment = new ArraySegment<byte>(buffer, 0, byteCount);
            await SendResponseAsync(message, segment, cancellationToken);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static async Task SendResponseAsync(
        DnsPacketReceivedMessage message,
        ArraySegment<byte> segment,
        CancellationToken cancellationToken
    )
    {
        await (message switch
            {
                TcpDnsPacketReceivedMessage tcpMessage =>
                    SendResponseAsync(
                        segment,
                        tcpMessage.Client,
                        cancellationToken
                    ),
                UdpDnsPacketReceivedMessage udpMessage =>
                    SendResponseAsync(
                        segment,
                        udpMessage.Client,
                        udpMessage.Context.ClientEndPoint,
                        cancellationToken
                    ),
                _ => Task.CompletedTask
            })
            .IgnoreExceptionsAsync(cancellationToken)
            .ConfigureAwait(false);
    }

    private static bool TryTruncateRecords(ref ImmutableArray<DomainResourceRecord> records)
    {
        if (records.Length <= 0)
            return false;

        records = records[..^1];
        return true;
    }

    private static int TruncateAndEncodeMessage(DomainMessage response, int sizeLimit, Span<byte> buffer)
    {
        while (true)
        {
            var byteCount = DomainMessageEncoder.Encode(buffer, response);
            if (byteCount <= sizeLimit) return byteCount;

            var (answers, authority, additional) = response.Records;
            if (TryTruncateRecords(ref additional))
            {
                response = response with { Records = response.Records with { Additional = additional } };
                continue;
            }

            if (TryTruncateRecords(ref authority))
            {
                response = response with { Records = response.Records with { Authorities = authority } };
                continue;
            }

            if (answers.Length > 1 && TryTruncateRecords(ref answers))
            {
                response = response with { Records = response.Records with { Answers = answers } };
                continue;
            }

            // We can't truncate it further, did the client send 100 questions or something? :sus:
            return DomainMessageEncoder.Encode(buffer, response);
        }
    }

    private static async Task SendResponseAsync(ArraySegment<byte> segment, UdpClient client, IPEndPoint clientEndPoint,
        CancellationToken cancellationToken)
    {
        await client.SendAsync(segment.AsMemory(), clientEndPoint, cancellationToken);
    }

    private static async Task SendResponseAsync(ArraySegment<byte> segment, TcpClient socket,
        CancellationToken cancellationToken)
    {
        await socket.Client.SendAsync(segment, cancellationToken);
    }

    public void Dispose()
    {
        _middlewareChain.Dispose();
    }
}