using System.Net;

using DNS.Client.RequestResolver;

using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;

namespace Dhcpr.Dns.Core;

public sealed class ResolverCache : IResolverCache
{
    private readonly IMemoryCache _memoryCache;
    private readonly ILogger<ResolverCache> _logger;

    public ResolverCache(IMemoryCache memoryCache, ILogger<ResolverCache> logger)
    {
        _memoryCache = memoryCache;
        _logger = logger;
    }

    public T GetResolver<T>(IPEndPoint endPoint, Func<IPEndPoint, T> createResolverCallback) where T : IRequestResolver
    {
        var key = ResolverCacheKey.Create<T>(endPoint);
        if (_memoryCache.TryGetValue<T>(key, out var resolver) && resolver is not null)
            return resolver;
        resolver = createResolverCallback.Invoke(endPoint);

        using var cacheEntry = _memoryCache.CreateEntry(key);
        cacheEntry.Value = resolver;
        cacheEntry.SetAbsoluteExpiration(DateTimeOffset.Now.AddHours(24));
        cacheEntry.SetSlidingExpiration(TimeSpan.FromMinutes(5));
        cacheEntry.Priority = CacheItemPriority.Low;
        cacheEntry.Dispose();
        _logger.LogInformation("Cache miss for resolver key: {key}, resolver {type}:{hashCode} created", key,
            resolver.GetType(), resolver.GetHashCode());
        return resolver;
    }

    public TOuter GetMultiResolver<TOuter, TInner>(IEnumerable<IPEndPoint> endPoints,
        Func<IEnumerable<IRequestResolver>, TOuter> createMultiResolver, Func<IPEndPoint, TInner> createInnerResolver)
        where TOuter : MultiResolver
        where TInner : IRequestResolver
    {
        using var orderedEndPoints = endPoints.OrderBy(i => i.ToString()).ToPooledList();
        var cacheKey =
            new MultiResolverCacheKey(
                orderedEndPoints.Select(i => new ResolverCacheKey(i, typeof(TInner))).ToArray(), typeof(TOuter));
        if (_memoryCache.TryGetValue<TOuter>(cacheKey, out var cachedResolver) && cachedResolver is not null)
            return cachedResolver;
        using var innerResolvers = orderedEndPoints.Select(i => GetResolver(i, createInnerResolver))
            .ToPooledList();
        cachedResolver = createMultiResolver.Invoke(innerResolvers.Cast<IRequestResolver>());
        using var cacheEntry = _memoryCache.CreateEntry(cacheKey);
        cacheEntry.Value = cachedResolver;
        cacheEntry.SetAbsoluteExpiration(DateTimeOffset.Now.AddHours(24));
        cacheEntry.SetSlidingExpiration(TimeSpan.FromMinutes(5));
        cacheEntry.Priority = CacheItemPriority.Low;
        cacheEntry.Dispose();

        return cachedResolver;
    }
}