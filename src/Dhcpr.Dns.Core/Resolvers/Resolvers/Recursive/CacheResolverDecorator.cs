using System.Collections.Concurrent;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Resolvers.Caching;

using Microsoft.Extensions.Logging;

namespace Dhcpr.Dns.Core.Resolvers.Resolvers.Recursive;

public sealed partial class CacheResolverDecorator : IDomainMessageMiddleware
{
    internal static readonly TimeSpan RefreshTimeout = TimeSpan.FromSeconds(10);

    private static readonly ConcurrentDictionary<DnsCacheKey, byte> _refreshing = new();

    private readonly IDomainMessageMiddleware _innerMiddleware;
    private readonly IDnsResponseCache _cache;
    private readonly IInternalDomainClient? _internalClient;
    private readonly ILogger<CacheResolverDecorator>? _logger;

    public CacheResolverDecorator(IDomainMessageMiddleware innerMiddleware, IDnsResponseCache cache)
        : this(innerMiddleware, cache, internalClient: null, logger: null)
    {
    }

    public CacheResolverDecorator(
        IDomainMessageMiddleware innerMiddleware,
        IDnsResponseCache cache,
        IInternalDomainClient? internalClient,
        ILogger<CacheResolverDecorator>? logger)
    {
        _innerMiddleware = innerMiddleware;
        _cache = cache;
        _internalClient = internalClient;
        _logger = logger;
    }

    public async ValueTask<DomainMessage> ProcessAsync(DomainMessageContext context,
        CancellationToken cancellationToken)
    {
        if (!context.BypassCache &&
            _cache.TryGet(context.DomainMessage, out var cached, out var securityStatus, out var shouldRefresh) &&
            cached is not null)
        {
            context.CacheHit = true;
            context.CachedDnssecStatus = securityStatus;
            context.AnsweredBy = "Cache";
            if (shouldRefresh)
                TryScheduleRefresh(context);
            return cached;
        }

        var result = await _innerMiddleware.ProcessAsync(context, cancellationToken);
        if (!context.DoNotCacheResponse)
            _cache.Set(context.DomainMessage, result);

        return result;
    }

    public string Name => _innerMiddleware.Name;
    public int Priority => _innerMiddleware.Priority;

    private void TryScheduleRefresh(DomainMessageContext context)
    {
        if (_internalClient is null)
            return;

        if (context.DomainMessage.Questions.Length != 1)
            return;

        var question = context.DomainMessage.Questions[0];
        var key = DnsCacheKey.FromQuestion(question);
        if (!_refreshing.TryAdd(key, 0))
            return;

        if (_logger is not null)
            LogRefresh(_logger, question.Name, question.Type);
        _ = RefreshAsync(context, question, key);
    }

    private async Task RefreshAsync(
        DomainMessageContext parent,
        DomainQuestion question,
        DnsCacheKey key)
    {
        try
        {
            using var timeout = new CancellationTokenSource(RefreshTimeout);
            var request = DomainMessage.CreateRequest(question.Name, question.Type, question.Class);
            var fresh = await _internalClient!
                .SendRefreshAsync(parent, request, timeout.Token)
                .ConfigureAwait(false);
            _cache.Set(request, fresh.Message, fresh.SecurityStatus);
        }
        catch (Exception exception)
        {
            if (_logger is not null)
                LogRefreshFailed(_logger, exception, question.Name, question.Type);
        }
        finally
        {
            _refreshing.TryRemove(key, out _);
        }
    }

    [LoggerMessage(Level = LogLevel.Debug, Message = "Refresh {Name} {Type}")]
    private static partial void LogRefresh(ILogger logger, DomainLabels name, DomainRecordType type);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Refresh {Name} {Type} failed")]
    private static partial void LogRefreshFailed(
        ILogger logger,
        Exception exception,
        DomainLabels name,
        DomainRecordType type);
}
