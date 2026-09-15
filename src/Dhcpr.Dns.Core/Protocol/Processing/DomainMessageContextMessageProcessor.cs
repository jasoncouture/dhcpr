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
    private readonly IUdpQueryRateLimiter _udpRateLimiter;
    private readonly Histogram<double> _duration;
    private readonly Counter<long> _queries;

    public DomainMessageContextMessageProcessor(
        IEnumerable<IDomainMessageMiddleware> middlewareChain,
        ILiveQueryEventPublisher liveQueryPublisher,
        IUdpQueryRateLimiter udpRateLimiter,
        ILogger<DomainMessageContextMessageProcessor> logger,
        IMeterFactory meterFactory)
    {
        _logger = logger;
        _liveQueryPublisher = liveQueryPublisher;
        _udpRateLimiter = udpRateLimiter;
        _middlewareChain = middlewareChain.OrderBy(i => i.Priority).ToPooledList();
        var meter = meterFactory.Create(DnsMetrics.MeterName);
        _duration = DnsMetrics.CreateDurationHistogram(
            meter,
            DnsMetrics.DurationInstrumentName,
            "DNS query processing duration");
        _queries = meter.CreateCounter<long>(
            DnsMetrics.QueriesInstrumentName,
            unit: "{query}",
            description: "DNS queries answered by a middleware handler");
    }

    public async Task ProcessMessageAsync(DnsPacketReceivedMessage message, CancellationToken cancellationToken)
    {
        var awaitable = message as IAwaitableDnsRequest;
        EdnsCookie.Capture(message.Context);
        using var activity = DnsInstrumentation.StartQuery(message);
        var started = Stopwatch.GetTimestamp();
        DomainMessage? response = null;
        try
        {
            IDomainMessageMiddleware? answeredBy = null;
            if (ShouldRateLimit(message.Context) &&
                TryApplyRateLimit(message.Context, out response))
            {
                // Rate-limit answers never enter MetricsDomainMessageMiddleware.
                if (response is not null)
                    DnsMetrics.RecordQueries(_queries, message.Context, response);
                else
                    DnsMetrics.RecordQueries(_queries, message.Context, DnsMetrics.DropRcode, error: true);
            }
            else
            {
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

            if (!message.Context.IsInternal)
                response = EdnsCookie.Apply(message.Context.ClientCookie, response);

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

            await SendResponseAsync(message, response, _logger, cancellationToken);
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
        ILogger logger,
        CancellationToken cancellationToken
    )
    {
        var isTcp = message is TcpDnsPacketReceivedMessage;
        // DNS-over-TCP prefixes every message with a 2-byte big-endian length.
        var lengthPrefix = isTcp ? 2 : 0;
        var buffer = ArrayPool<byte>.Shared.Rent(Math.Max(65_535, response.EstimatedSize) + lengthPrefix);

        if (!isTcp)
            response = ApplyUdpAmplificationGuard(response, logger, message.Context.ClientEndPoint);

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
    /// Classic DNS only (UDP and TCP). DoT, DoH, and internal hops are not
    /// limited.
    /// </summary>
    private static bool ShouldRateLimit(DomainMessageContext context)
        => !context.IsInternal &&
           context.Source is DnsQuerySource.Udp or DnsQuerySource.Tcp;

    /// <summary>
    /// Returns <see langword="true"/> when a UDP/TCP client is over the
    /// sliding window. <paramref name="response"/> is a REFUSED message, or
    /// null to drop.
    /// </summary>
    private bool TryApplyRateLimit(DomainMessageContext context, out DomainMessage? response)
    {
        var question = context.DomainMessage.Questions is [{ } q, ..] ? q : null;
        var action = _udpRateLimiter.Record(
            context.ClientEndPoint?.Address,
            question?.Name ?? DomainLabels.Empty,
            question?.Type ?? default);
        if (action is UdpRateLimitAction.Allow)
        {
            response = null;
            return false;
        }

        context.AnsweredBy = "UdpRateLimit";
        if (action is UdpRateLimitAction.Drop)
        {
            context.Cancel = true;
            LogUdpRateLimitDrop(
                _logger,
                context.ClientEndPoint,
                question?.Type ?? default,
                question?.Name ?? DomainLabels.Empty);
            response = null;
            return true;
        }

        LogUdpRateLimitRefuse(
            _logger,
            context.ClientEndPoint,
            question?.Type ?? default,
            question?.Name ?? DomainLabels.Empty);
        response = DomainMessage.CreateResponse(
            context.DomainMessage,
            DomainResourceRecords.Empty,
            DomainResponseCode.Refused);
        return true;
    }

    /// <summary>
    /// If the assembled answer would exceed <see cref="UdpResponseSizeLimit"/>
    /// on UDP, return TC with empty RRsets so the datagram stays tiny.
    /// Legitimate clients retry over TCP.
    /// </summary>
    public static DomainMessage ApplyUdpAmplificationGuard(
        DomainMessage response,
        ILogger? logger = null,
        IPEndPoint? client = null)
    {
        if (response.EstimatedSize <= UdpResponseSizeLimit)
            return response;

        if (logger is not null)
        {
            var question = response.Questions is [{ } q, ..] ? q : null;
            LogUdpAmplificationGuard(
                logger,
                client,
                question?.Type ?? default,
                question?.Name ?? DomainLabels.Empty,
                response.EstimatedSize,
                UdpResponseSizeLimit);
        }

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

    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Rate limit REFUSED {Name}/{QueryType} from {Client}")]
    private static partial void LogUdpRateLimitRefuse(
        ILogger logger,
        IPEndPoint? client,
        DomainRecordType queryType,
        DomainLabels name);

    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Rate limit drop {Name}/{QueryType} from {Client}")]
    private static partial void LogUdpRateLimitDrop(
        ILogger logger,
        IPEndPoint? client,
        DomainRecordType queryType,
        DomainLabels name);

    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "UDP amplification guard truncated {Name}/{QueryType} from {Client} size={Size} limit={Limit}")]
    private static partial void LogUdpAmplificationGuard(
        ILogger logger,
        IPEndPoint? client,
        DomainRecordType queryType,
        DomainLabels name,
        int size,
        int limit);
}