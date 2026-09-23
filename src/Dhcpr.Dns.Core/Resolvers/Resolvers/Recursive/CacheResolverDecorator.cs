using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Resolvers.Caching;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Dhcpr.Dns.Core.Resolvers.Resolvers.Recursive;

public sealed partial class CacheResolverDecorator : IDomainMessageMiddleware
{
    private readonly IDomainMessageMiddleware _innerMiddleware;
    private readonly IDnsResponseCache _cache;
    private readonly IServiceScopeFactory _scopes;

    public CacheResolverDecorator(
        IDomainMessageMiddleware innerMiddleware,
        IDnsResponseCache cache,
        IServiceScopeFactory scopes)
    {
        _innerMiddleware = innerMiddleware;
        _cache = cache;
        _scopes = scopes;
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
                RefreshAsync(context);
            return cached;
        }

        var result = await _innerMiddleware.ProcessAsync(context, cancellationToken);
        if (!context.DoNotCacheResponse)
            _cache.Set(context.DomainMessage, result);

        return result;
    }

    // ReSharper disable once AsyncVoidMethod - If any of this throws, something is horribly wrong.
    private async void RefreshAsync(DomainMessageContext context)
    {
        await Task.Yield();
        await using var scope = _scopes.CreateAsyncScope();
        var logger = scope.ServiceProvider.GetRequiredService<ILogger<CacheResolverDecorator>>();
        try
        {
            var refresh = scope.ServiceProvider.GetRequiredService<IDnsCacheRefresh>();
            await refresh.RefreshAsync(context).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            var question = context.DomainMessage.Questions[0];
            LogRefreshFailed(logger, exception, question.Name, question.Type);
        }
    }

    public string Name => _innerMiddleware.Name;
    public int Priority => _innerMiddleware.Priority;

    [LoggerMessage(Level = LogLevel.Debug, Message = "Refresh {Name} {Type} failed")]
    private static partial void LogRefreshFailed(
        ILogger logger,
        Exception exception,
        DomainLabels name,
        DomainRecordType type);
}
