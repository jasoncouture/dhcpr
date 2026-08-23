using System.Buffers;
using System.Collections.Immutable;
using System.Linq;
using System.Net;
using System.Net.Sockets;

using Dhcpr.Core;
using Dhcpr.Core.Linq;
using Dhcpr.Core.Queue;
using Dhcpr.Dns.Core.Protocol.Parser;

using Microsoft.Extensions.Logging;

namespace Dhcpr.Dns.Core.Protocol.Processing;

public sealed partial class DomainMessageContextMessageProcessor : IQueueMessageProcessor<DnsPacketReceivedMessage>, IDisposable
{
    private readonly ILogger<DomainMessageContextMessageProcessor> _logger;
    private readonly PooledList<IDomainMessageMiddleware> _middlewareChain;
    private readonly IEdnsProtocolService _ednsProtocolService;
    private readonly ILiveQueryEventPublisher _liveQueryPublisher;

    public DomainMessageContextMessageProcessor(
        IEnumerable<IDomainMessageMiddleware> middlewareChain,
        IEdnsProtocolService ednsProtocolService,
        ILiveQueryEventPublisher liveQueryPublisher,
        ILogger<DomainMessageContextMessageProcessor> logger)
    {
        _logger = logger;
        _ednsProtocolService = ednsProtocolService;
        _liveQueryPublisher = liveQueryPublisher;
        _middlewareChain = middlewareChain.OrderBy(i => i.Priority).ToPooledList();
    }

    public async Task ProcessMessageAsync(DnsPacketReceivedMessage message, CancellationToken cancellationToken)
    {
        var awaitable = message as IAwaitableDnsRequest;
        try
        {
            DomainMessage? response = null;
            IDomainMessageMiddleware? answeredBy = null;
            foreach (var middleware in _middlewareChain)
            {
                response = await middleware.ProcessAsync(message.Context, cancellationToken);
                if (message.Context.Cancel) // This is intended for things that want to ignore the request.
                    break;
                if (response is not null) // This is intended for things to say "I don't handle this, try next"
                {
                    answeredBy = middleware;
                    break;
                }
            }

            // This is a directive to ignore the message.
            // The middleware may have responded to it, or may be blocking this client.
            // Awaitable clients (internal / DNS-over-HTTP) treat null as failure via TrySetResult(null).
            if (response is null)
            {
                awaitable?.TaskCompletionSource.TrySetResult(null);
                return;
            }

            if (response.Id != message.Context.DomainMessage.Id)
            {
                response = response with { Id = message.Context.DomainMessage.Id };
            }

            // Publish once per external client answer (UDP/TCP/DoH), independent of decorate order.
            await DnsQueryEventFactory.PublishAnswersAsync(
                _liveQueryPublisher,
                message.Context,
                response,
                message.Context.AnsweredBy ?? answeredBy?.Name ?? "unknown",
                cancellationToken);

            if (awaitable is not null)
            {
                awaitable.TaskCompletionSource.TrySetResult(response);
                return;
            }

            await SendResponseAsync(message, response, _ednsProtocolService, cancellationToken);
        }
        catch (Exception ex)
        {
            if (awaitable is not null)
            {
                awaitable.TaskCompletionSource.TrySetException(ex);
                return;
            }

            LogProcessMessageFailed(_logger, ex);
        }
        finally
        {
            if (message is TcpDnsPacketReceivedMessage tcp)
                tcp.SendCompleted.TrySetResult();
        }
    }

    private static async Task SendResponseAsync(
        DnsPacketReceivedMessage message,
        DomainMessage response,
        IEdnsProtocolService ednsProtocolService,
        CancellationToken cancellationToken
    )
    {
        var isTcp = message is TcpDnsPacketReceivedMessage;
        // DNS-over-TCP prefixes every message with a 2-byte big-endian length.
        var lengthPrefix = isTcp ? 2 : 0;
        var buffer = ArrayPool<byte>.Shared.Rent(Math.Max(65_535, response.EstimatedSize) + lengthPrefix);

        var udpLimit = 512;
        var optRecord = message.Context.DomainMessage.Records.Additional.FirstOrDefault(r => r.Type == DomainRecordType.OPT);
        if (optRecord is not null)
        {
            var requestedSize = ednsProtocolService.GetUdpPayloadSize(optRecord);
            if (requestedSize >= 512)
            {
                udpLimit = requestedSize;
            }
        }

        try
        {
            var byteCount = TruncateAndEncodeMessage(
                response,
                isTcp ? int.MaxValue : udpLimit,
                buffer.AsSpan(lengthPrefix)
            );
            if (isTcp)
                BitConverter.TryWriteBytes(buffer.AsSpan(0, 2), ((ushort)byteCount).ToNetworkByteOrder());

            var segment = new ArraySegment<byte>(buffer, 0, byteCount + lengthPrefix);
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
            UdpDnsPacketReceivedMessage { Context.ClientEndPoint: { } clientEndPoint } udpMessage =>
                SendResponseAsync(
                    segment,
                    udpMessage.Client,
                    clientEndPoint,
                    cancellationToken
                ),
            _ => Task.CompletedTask
        })
            .IgnoreExceptionsAsync(cancellationToken)
            .ConfigureAwait(false);
    }

    private static ImmutableArray<DomainResourceRecord>? TryTruncateRecords(
        ImmutableArray<DomainResourceRecord> records)
    {
        if (records.Length <= 0)
            return null;

        return records[..^1];
    }

    public static int TruncateAndEncodeMessage(DomainMessage response, int sizeLimit, Span<byte> buffer)
    {
        while (true)
        {
            var byteCount = DomainMessageEncoder.Encode(buffer, response);
            if (byteCount <= sizeLimit) return byteCount;

            var (answers, authority, additional) = response.Records;
            if (TryTruncateRecords(additional) is { } truncatedAdditional)
            {
                response = response with
                {
                    Flags = response.Flags with { Truncated = true },
                    Records = response.Records with { Additional = truncatedAdditional }
                };
                continue;
            }

            if (TryTruncateRecords(authority) is { } truncatedAuthority)
            {
                response = response with
                {
                    Flags = response.Flags with { Truncated = true },
                    Records = response.Records with { Authorities = truncatedAuthority }
                };
                continue;
            }

            if (answers.Length > 1 && TryTruncateRecords(answers) is { } truncatedAnswers)
            {
                response = response with
                {
                    Flags = response.Flags with { Truncated = true },
                    Records = response.Records with { Answers = truncatedAnswers }
                };
                continue;
            }

            // We can't truncate it further, did the client send 100 questions or something? :sus:
            response = response with { Flags = response.Flags with { Truncated = true } };
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

    [LoggerMessage(Level = LogLevel.Error, Message = "Failed to process message due to an exception")]
    private static partial void LogProcessMessageFailed(ILogger logger, Exception exception);
}