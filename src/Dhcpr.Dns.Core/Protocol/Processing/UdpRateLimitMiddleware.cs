using System.Net;

using Microsoft.Extensions.Logging;

namespace Dhcpr.Dns.Core.Protocol.Processing;

/// <summary>
/// REFUSED or drop for classic DNS (UDP and TCP) over the shared sliding
/// window. Outside the cache. Inside the loop check, so a tagged self-query
/// is REFUSED before this counts it.
/// </summary>
public sealed partial class UdpRateLimitMiddleware : IDomainMessageMiddleware
{
    private readonly IDomainMessageMiddleware _inner;
    private readonly IUdpQueryRateLimiter _rateLimiter;
    private readonly ILogger<UdpRateLimitMiddleware> _logger;

    public UdpRateLimitMiddleware(
        IDomainMessageMiddleware inner,
        IUdpQueryRateLimiter rateLimiter,
        ILogger<UdpRateLimitMiddleware> logger)
    {
        _inner = inner;
        _rateLimiter = rateLimiter;
        _logger = logger;
    }

    public string Name => _inner.Name;
    public int Priority => _inner.Priority;

    public async ValueTask<DomainMessage> ProcessAsync(
        DomainMessageContext context,
        CancellationToken cancellationToken)
    {
        if (!ShouldRateLimit(context))
            return await _inner.ProcessAsync(context, cancellationToken).ConfigureAwait(false);

        var question = context.DomainMessage.Questions is [{ } q, ..] ? q : null;
        var action = _rateLimiter.Record(
            context.ClientEndPoint?.Address,
            question?.Name ?? DomainLabels.Empty,
            question?.Type ?? default);
        if (action is UdpRateLimitAction.Allow)
            return await _inner.ProcessAsync(context, cancellationToken).ConfigureAwait(false);

        context.AnsweredBy = "UdpRateLimit";
        if (action is UdpRateLimitAction.Drop)
        {
            context.Cancel = true;
            LogUdpRateLimitDrop(
                _logger,
                context.ClientEndPoint,
                question?.Type ?? default,
                question?.Name ?? DomainLabels.Empty);
        }
        else
        {
            LogUdpRateLimitRefuse(
                _logger,
                context.ClientEndPoint,
                question?.Type ?? default,
                question?.Name ?? DomainLabels.Empty);
        }

        return DomainMessage.CreateResponse(
            context.DomainMessage,
            DomainResourceRecords.Empty,
            DomainResponseCode.Refused);
    }

    private static bool ShouldRateLimit(DomainMessageContext context)
        => !context.IsInternal &&
           !context.CookieConfirmed &&
           context.Source is DnsQuerySource.Udp or DnsQuerySource.Tcp;

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
}
