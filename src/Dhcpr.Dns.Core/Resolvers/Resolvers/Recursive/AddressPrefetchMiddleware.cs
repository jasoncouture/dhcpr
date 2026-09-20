using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Resolvers.Caching;

using Microsoft.Extensions.Logging;

namespace Dhcpr.Dns.Core.Resolvers.Resolvers.Recursive;

/// <summary>
/// After an external IN A or AAAA miss, fill the sibling type in cache.
/// Lives inside the response cache (immediately inside ServFailRetry).
/// Never prefetches from an internal hop or a prefetch hop (A ⇄ AAAA loop).
/// </summary>
public sealed partial class AddressPrefetchMiddleware : IDomainMessageMiddleware
{
    internal static readonly TimeSpan PrefetchTimeout = TimeSpan.FromSeconds(10);

    private readonly IDomainMessageMiddleware _inner;
    private readonly IDnsResponseCache _cache;
    private readonly IInternalDomainClient _internalClient;
    private readonly ILogger<AddressPrefetchMiddleware> _logger;

    public AddressPrefetchMiddleware(
        IDomainMessageMiddleware inner,
        IDnsResponseCache cache,
        IInternalDomainClient internalClient,
        ILogger<AddressPrefetchMiddleware> logger)
    {
        _inner = inner;
        _cache = cache;
        _internalClient = internalClient;
        _logger = logger;
    }

    public string Name => _inner.Name;
    public int Priority => _inner.Priority;

    public async ValueTask<DomainMessage> ProcessAsync(
        DomainMessageContext context,
        CancellationToken cancellationToken)
    {
        var result = await _inner.ProcessAsync(context, cancellationToken).ConfigureAwait(false);
        TrySchedulePrefetch(context, result);
        return result;
    }

    internal static DomainRecordType? SiblingType(DomainRecordType type)
        => type switch
        {
            DomainRecordType.A => DomainRecordType.AAAA,
            DomainRecordType.AAAA => DomainRecordType.A,
            _ => null
        };

    private void TrySchedulePrefetch(DomainMessageContext context, DomainMessage result)
    {
        if (context.IsInternal || context.SuppressAddressPrefetch)
            return;

        if (context.BypassCache || context.UpstreamEndpoints is { Length: > 0 })
            return;

        if (result.Flags.ResponseCode is not DomainResponseCode.NoError)
            return;

        if (context.DomainMessage.Questions.Length != 1)
            return;

        var question = context.DomainMessage.Questions[0];
        if (question.Class is not DomainRecordClass.IN)
            return;

        if (SiblingType(question.Type) is not { } sibling)
            return;

        var siblingRequest = DomainMessage.CreateRequest(question.Name, sibling);
        if (_cache.TryGet(siblingRequest, out _))
            return;

        LogPrefetch(_logger, question.Name, sibling);
        _ = PrefetchAsync(context, siblingRequest);
    }

    private async Task PrefetchAsync(DomainMessageContext parent, DomainMessage siblingRequest)
    {
        try
        {
            using var timeout = new CancellationTokenSource(PrefetchTimeout);
            await _internalClient
                .SendPrefetchAsync(parent, siblingRequest, timeout.Token)
                .ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            LogPrefetchFailed(_logger, exception, siblingRequest.Questions[0].Name, siblingRequest.Questions[0].Type);
        }
    }

    [LoggerMessage(Level = LogLevel.Debug, Message = "Prefetch {Name} {Type}")]
    private static partial void LogPrefetch(ILogger logger, DomainLabels name, DomainRecordType type);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Prefetch {Name} {Type} failed")]
    private static partial void LogPrefetchFailed(
        ILogger logger,
        Exception exception,
        DomainLabels name,
        DomainRecordType type);
}
