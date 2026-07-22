using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Resolvers.Caching;

namespace Dhcpr.Dns.Core.Resolvers.Resolvers.Recursive;

public sealed class CacheResolverDecorator : IDomainMessageMiddleware
{
    private readonly IDomainMessageMiddleware _innerMiddleware;
    private readonly IDnsResponseCache _cache;
    private readonly CacheState _cacheState;

    public CacheResolverDecorator(IDomainMessageMiddleware innerMiddleware, IDnsResponseCache cache, CacheState cacheState)
    {
        _innerMiddleware = innerMiddleware;
        _cache = cache;
        _cacheState = cacheState;
    }

    public async ValueTask<DomainMessage?> ProcessAsync(DomainMessageContext context,
        CancellationToken cancellationToken)
    {
        if (_cache.TryGet(context.DomainMessage, out var cached) && cached is not null)
        {
            _cacheState.CacheHit = true;
            return cached;
        }

        var result = await _innerMiddleware.ProcessAsync(context, cancellationToken);
        if (result is not null)
            _cache.Set(context.DomainMessage, result);

        return result;
    }

    public string Name => _innerMiddleware.Name;
    public int Priority => _innerMiddleware.Priority;
}
