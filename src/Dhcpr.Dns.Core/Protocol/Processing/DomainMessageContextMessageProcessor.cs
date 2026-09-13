using System.Buffers;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Diagnostics.Metrics;
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
    /// <summary>
    /// Hard UDP payload cap. Client EDNS sizes above this are ignored so a
    /// spoofed cisco.com TXT cannot be used as an amplifier.
    /// </summary>
    public const int UdpResponseSizeLimit = 1232;

    private readonly ILogger<DomainMessageContextMessageProcessor> _logger;
    private readonly PooledList<IDomainMessageMiddleware> _middlewareChain;
    private readonly ILiveQueryEventPublisher _liveQueryPublisher;
    private readonly Histogram<double> _duration;

    public DomainMessageContextMessageProcessor(
        IEnumerable<IDomainMessageMiddleware> middlewareChain,
        ILiveQueryEventPublisher liveQueryPublisher,
        ILogger<DomainMessageContextMessageProcessor> logger,
        IMeterFactory meterFactory)
    {
        _logger = logger;
        _liveQueryPublisher = liveQueryPublisher;
        _middlewareChain = middlewareChain.OrderBy(i => i.Priority).ToPooledList();
        _duration = meterFactory.Create(DnsMetrics.MeterName).CreateHistogram<double>(
            DnsMetrics.DurationInstrumentName,
            unit: "s",
            description: "DNS query processing duration");
    }

    public async Task ProcessMessageAsync(DnsPacketReceivedMessage message, CancellationToken cancellationToken)
    {
        var awaitable = message as IAwaitableDnsRequest;
        using var activity = DnsInstrumentation.StartQuery(message);
        var started = Stopwatch.GetTimestamp();
        DomainMessage? response = null;
        try
        {
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

            if (message.Context.AnsweredBy is null && answeredBy is not null)
                message.Context.AnsweredBy = answeredBy.Name;

            DnsInstrumentation.CompleteQuery(activity, message.Context, response);
            DnsInstrumentation.RecordDuration(
                _duration,
                message.Context,
                response,
                Stopwatch.GetElapsedTime(started));

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

            await SendResponseAsync(message, response, cancellationToken);
        }
        catch (Exception ex)
        {
            activity?.SetStatus(ActivityStatusCode.Error, ex.Message);
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
        CancellationToken cancellationToken
    )
    {
        var isTcp = message is TcpDnsPacketReceivedMessage;
        // DNS-over-TCP prefixes every message with a 2-byte big-endian length.
        var lengthPrefix = isTcp ? 2 : 0;
        var buffer = ArrayPool<byte>.Shared.Rent(Math.Max(65_535, response.EstimatedSize) + lengthPrefix);

        if (!isTcp)
            response = ApplyUdpAmplificationGuard(response);

        try
        {
            var byteCount = TruncateAndEncodeMessage(
                response,
                isTcp ? int.MaxValue : UdpResponseSizeLimit,
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
                    tcpMessage.Stream,
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

    /// <summary>
    /// If the assembled answer would exceed <see cref="UdpResponseSizeLimit"/>
    /// on UDP, return TC with empty RRsets so the datagram stays tiny.
    /// Legitimate clients retry over TCP.
    /// </summary>
    public static DomainMessage ApplyUdpAmplificationGuard(DomainMessage response)
    {
        if (response.EstimatedSize <= UdpResponseSizeLimit)
            return response;

        return response with
        {
            Flags = response.Flags with { Truncated = true },
            Records = DomainResourceRecords.Empty
        };
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

    private static async Task SendResponseAsync(ArraySegment<byte> segment, Stream stream,
        CancellationToken cancellationToken)
    {
        await stream.WriteAsync(segment, cancellationToken);
    }

    public void Dispose()
    {
        _middlewareChain.Dispose();
    }

    [LoggerMessage(Level = LogLevel.Error, Message = "Failed to process message due to an exception")]
    private static partial void LogProcessMessageFailed(ILogger logger, Exception exception);
}