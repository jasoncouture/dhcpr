using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Resolvers.Caching;

namespace Dhcpr.Dns.Core.Resolvers.Resolvers.Recursive;

public sealed class CacheResolverDecorator : IDomainMessageMiddleware
{
    private readonly IDomainMessageMiddleware _innerMiddleware;
    private readonly IDnsResponseCache _cache;

    public CacheResolverDecorator(IDomainMessageMiddleware innerMiddleware, IDnsResponseCache cache)
    {
        _innerMiddleware = innerMiddleware;
        _cache = cache;
    }

    public async ValueTask<DomainMessage?> ProcessAsync(DomainMessageContext context,
        CancellationToken cancellationToken)
    {
        if (!context.BypassCache &&
            _cache.TryGet(context.DomainMessage, out var cached, out var securityStatus) &&
            cached is not null)
        {
            context.CacheHit = true;
            context.CachedDnssecStatus = securityStatus;
            return cached;
        }

        var result = await _innerMiddleware.ProcessAsync(context, cancellationToken);
        if (result is not null && !context.DoNotCacheResponse)
            _cache.Set(context.DomainMessage, result);

        return result;
    }

    public string Name => _innerMiddleware.Name;
    public int Priority => _innerMiddleware.Priority;
}
