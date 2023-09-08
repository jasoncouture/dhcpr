using System.Net;

using Dhcpr.Core.Linq;
using Dhcpr.Dns.Core.Resolvers.Resolvers.Abstractions;

using DNS.Client.RequestResolver;

using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Dhcpr.Dns.Core.Resolvers.Caching;

public sealed class ResolverCache : IResolverCache
{
    private readonly IMemoryCache _memoryCache;
    private readonly ILogger<ResolverCache> _logger;
    private readonly IServiceProvider _serviceProvider;

    public ResolverCache(IMemoryCache memoryCache, ILogger<ResolverCache> logger, IServiceProvider serviceProvider)
    {
        _memoryCache = memoryCache;
        _logger = logger;
        _serviceProvider = serviceProvider;
    }

    public T GetResolver<T>(IPEndPoint endPoint, Func<IPEndPoint, T> createResolverCallback) where T : IRequestResolver
    {
        var key = ResolverCacheKey.Create<T>(endPoint);
        return GetFromCache<ResolverCacheKey, T>(key) ?? AddToCache(key, createResolverCallback.Invoke(endPoint));
    }

    private T? GetFromCache<TKey, T>(TKey key) where TKey : notnull
        where T : IRequestResolver
    {
        _memoryCache.TryGetValue<T>(key, out var resolver);

        return resolver;
    }

    private T AddToCache<TKey, T>(TKey key, T resolver)
        where TKey : notnull
        where T : IRequestResolver
    {
        using var cacheEntry = _memoryCache.CreateEntry(key);
        cacheEntry.Value = resolver;
        cacheEntry.SetAbsoluteExpiration(DateTimeOffset.Now.AddHours(24));
        cacheEntry.SetSlidingExpiration(TimeSpan.FromMinutes(5));
        cacheEntry.Priority = CacheItemPriority.Low;
        cacheEntry.Dispose();
        return resolver;
    }

    public ICachedResolver GetCacheForResolver(IRequestResolver resolver)
    {
        var key = CachedResolverCacheKey.FromInstance(resolver);
        return GetFromCache<CachedResolverCacheKey, CachedResolver>(key) ??
               AddToCache(key, ActivatorUtilities.CreateInstance<CachedResolver>(_serviceProvider, resolver));
    }

    public TOuter GetResolver<TOuter, TInner>(IEnumerable<IPEndPoint> endPoints,
        Func<IEnumerable<IRequestResolver>, TOuter> createMultiResolver, Func<IPEndPoint, TInner> createInnerResolver)
        where TOuter : MultiResolver
        where TInner : IRequestResolver
    {
        using var orderedEndPoints = endPoints.OrderBy(i => i.ToString()).ToPooledList();
        var cacheKey =
            new MultiResolverCacheKey(
                orderedEndPoints.Select(i => new ResolverCacheKey(i, typeof(TInner))).ToArray(), typeof(TOuter));

        return GetFromCache<MultiResolverCacheKey, TOuter>(cacheKey) ?? AddToCache(cacheKey,
            createMultiResolver.Invoke(orderedEndPoints.Select(i => GetResolver<TInner>(i, createInnerResolver))
                .Cast<IRequestResolver>()));
    }
}