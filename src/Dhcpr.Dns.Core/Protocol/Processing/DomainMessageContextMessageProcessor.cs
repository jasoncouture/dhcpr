using System.Buffers;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

using Dhcpr.Core;
using Dhcpr.Dns.Core.Protocol.Parser;

using Microsoft.Extensions.Logging;

namespace Dhcpr.Dns.Core.Protocol.Processing;

public sealed partial class DomainMessageContextMessageProcessor
{
    /// <summary>
    /// Hard UDP payload cap. Client EDNS sizes above this are ignored so a
    /// spoofed cisco.com TXT cannot be used as an amplifier.
    /// </summary>
    public const int UdpResponseSizeLimit = 1232;

    private readonly ILogger<DomainMessageContextMessageProcessor> _logger;
    private readonly IDomainMessageMiddleware _middleware;
    private readonly ILiveQueryEventPublisher _liveQueryPublisher;
    private readonly IUdpQueryRateLimiter _udpRateLimiter;
    private readonly IDnsMetrics _metrics;
    private readonly IDnsServerCookieFactory? _cookies;

    public DomainMessageContextMessageProcessor(
        IDomainMessageMiddleware middleware,
        ILiveQueryEventPublisher liveQueryPublisher,
        IUdpQueryRateLimiter udpRateLimiter,
        ILogger<DomainMessageContextMessageProcessor> logger,
        IDnsMetrics metrics,
        IDnsServerCookieFactory? cookies = null)
    {
        _middleware = middleware;
        _logger = logger;
        _liveQueryPublisher = liveQueryPublisher;
        _udpRateLimiter = udpRateLimiter;
        _metrics = metrics;
        _cookies = cookies;
    }

    public async ValueTask<DomainMessage?> ExecuteAsync(
        DomainMessageContext context,
        CancellationToken cancellationToken)
    {
        EdnsCookie.Capture(context, _cookies);
        using var activity = DnsInstrumentation.StartQuery(context);
        var started = Stopwatch.GetTimestamp();
        DomainMessage? response = null;
        try
        {
            IDomainMessageMiddleware? answeredBy = null;
            if (ShouldRateLimit(context) &&
                TryApplyRateLimit(context, out response))
            {
                // Rate-limit answers never enter MetricsDomainMessageMiddleware.
                if (response is not null)
                    _metrics.RecordQuery(context, response);
                else
                    _metrics.RecordQuery(context, DnsMetrics.DropRcode, error: true);
            }
            else
            {
                response = await _middleware.ProcessAsync(context, cancellationToken).ConfigureAwait(false);
                if (!context.Cancel)
                    answeredBy = _middleware;
            }

            if (context.AnsweredBy is null && answeredBy is not null)
                context.AnsweredBy = answeredBy.Name;

            DnsInstrumentation.CompleteQuery(activity, context, response);
            _metrics.RecordDuration(
                context,
                response,
                Stopwatch.GetElapsedTime(started));

            if (response is null)
                return null;

            if (response.Id != context.DomainMessage.Id)
                response = response with { Id = context.DomainMessage.Id };

            if (!context.IsInternal)
                response = EdnsCookie.Apply(
                    context.ClientCookie,
                    response,
                    _cookies,
                    context.ClientEndPoint?.Address);

            await DnsQueryEventFactory.PublishAnswersAsync(
                _liveQueryPublisher,
                context,
                response,
                context.AnsweredBy ?? answeredBy?.Name ?? "unknown",
                cancellationToken).ConfigureAwait(false);

            return response;
        }
        catch (Exception ex)
        {
            activity?.SetStatus(ActivityStatusCode.Error, ex.Message);
            throw;
        }
    }

    /// <summary>
    /// Classic DNS only (UDP and TCP). DoT, DoH, internal hops, and queries
    /// with a valid server cookie are not limited. A valid cookie means the
    /// source is not spoofed; cookies are never required.
    /// </summary>
    private static bool ShouldRateLimit(DomainMessageContext context)
        => !context.IsInternal &&
           !context.CookieConfirmed &&
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

    public static async Task WriteUdpAsync(
        UdpClient client,
        IPEndPoint clientEndPoint,
        DomainMessage response,
        ILogger logger,
        CancellationToken cancellationToken)
    {
        response = ApplyUdpAmplificationGuard(response, logger, clientEndPoint);
        var buffer = ArrayPool<byte>.Shared.Rent(Math.Max(65_535, response.EstimatedSize));
        try
        {
            var byteCount = TruncateAndEncodeMessage(response, UdpResponseSizeLimit, buffer);
            await client.SendAsync(buffer.AsMemory(0, byteCount), clientEndPoint, cancellationToken)
                .AsTask()
                .IgnoreExceptionsAsync(cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    public static async Task WriteTcpAsync(
        Stream stream,
        DomainMessage response,
        CancellationToken cancellationToken)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(Math.Max(65_535, response.EstimatedSize) + 2);
        try
        {
            var byteCount = TruncateAndEncodeMessage(response, int.MaxValue, buffer.AsSpan(2));
            BitConverter.TryWriteBytes(buffer.AsSpan(0, 2), ((ushort)byteCount).ToNetworkByteOrder());
            await stream.WriteAsync(buffer.AsMemory(0, byteCount + 2), cancellationToken)
                .AsTask()
                .IgnoreExceptionsAsync(cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

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
