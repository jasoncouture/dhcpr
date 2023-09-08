using Dhcpr.Dns.Core.Resolvers.Caching;

using DNS.Protocol;

using Microsoft.Extensions.Caching.Memory;

namespace Dhcpr.Dns.Core;

public class DnsMemoryCacheWriter : IDnsMemoryCacheWriter
{
    private readonly IMemoryCache _memoryCache;

    public DnsMemoryCacheWriter(IMemoryCache memoryCache)
    {
        _memoryCache = memoryCache;
    }

    public void AddToMemoryCache(QueryCacheKey key, IResponse? response, TimeSpan timeToLive)
    {
        if (response is null) return;
        key = key with { Domain = key.Domain.ToLower() };
        using var cacheEntry = _memoryCache.CreateEntry(key);
        var cacheData = new QueryCacheData(new NoCacheResponse(response), timeToLive);
        cacheEntry.Value = cacheData;
        cacheEntry.AbsoluteExpirationRelativeToNow = timeToLive;
        cacheEntry.Priority = CacheItemPriority.High;
    }
}