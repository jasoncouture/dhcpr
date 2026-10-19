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
    private readonly IQuerySingleFlight? _singleFlight;

    public CacheResolverDecorator(
        IDomainMessageMiddleware innerMiddleware,
        IDnsResponseCache cache,
        IServiceScopeFactory scopes,
        IQuerySingleFlight? singleFlight = null)
    {
        _innerMiddleware = innerMiddleware;
        _cache = cache;
        _scopes = scopes;
        _singleFlight = singleFlight;
    }

    public async ValueTask<DomainMessage> ProcessAsync(DomainMessageContext context,
        CancellationToken cancellationToken)
    {
        if (TryServeCached(context, out var cached))
            return cached;

        if (_singleFlight is not null && CanShare(context))
        {
            var request = context.DomainMessage;
            var join = await _singleFlight.JoinAsync(
                request.Questions[0],
                async token =>
                {
                    if (TryServeCached(context, out var raced))
                        return raced;
                    var resolved = await _innerMiddleware.ProcessAsync(context, token).ConfigureAwait(false);
                    if (!context.DoNotCacheResponse)
                        _cache.Set(context.DomainMessage, resolved);
                    return resolved;
                },
                cancellationToken).ConfigureAwait(false);

            if (!join.Shared)
                return join.Message;

            context.CacheHit = true;
            context.AnsweredBy = "Coalesced";
            if (join.Message.Flags.ResponseCode is DomainResponseCode.ServerFailure)
                context.ServFailReason ??= "coalesced server failure";

            return join.Message with
            {
                Id = request.Id,
                Questions = request.Questions,
                Flags = join.Message.Flags with { RecursionDesired = request.Flags.RecursionDesired }
            };
        }

        var result = await _innerMiddleware.ProcessAsync(context, cancellationToken);
        if (!context.DoNotCacheResponse)
            _cache.Set(context.DomainMessage, result);

        return result;
    }

    private bool TryServeCached(DomainMessageContext context, out DomainMessage cached)
    {
        cached = null!;
        if (context.BypassCache)
            return false;
        if (!_cache.TryGet(context.DomainMessage, out var hit, out var securityStatus, out var shouldRefresh) ||
            hit is null)
            return false;

        context.CacheHit = true;
        context.CachedDnssecStatus = securityStatus;
        context.AnsweredBy = "Cache";
        if (shouldRefresh)
            RefreshAsync(context);
        if (hit.Flags.ResponseCode is DomainResponseCode.ServerFailure)
            hit = EdnsExtendedError.Attach(hit, EdnsExtendedError.CachedError);
        cached = hit;
        return true;
    }

    private static bool CanShare(DomainMessageContext context)
        => !context.BypassCache &&
           context.UpstreamEndpoints is not { Length: > 0 } &&
           context.DomainMessage.Questions.Length == 1;

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
