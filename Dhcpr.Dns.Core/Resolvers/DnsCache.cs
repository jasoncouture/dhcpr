using System.Diagnostics.CodeAnalysis;

using DNS.Protocol;

using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;

namespace Dhcpr.Dns.Core;

public class DnsCache : IDnsCache
{
    private readonly IMemoryCache _memoryCache;
    private readonly ILogger<DnsCache> _logger;

    public DnsCache(IMemoryCache memoryCache, ILogger<DnsCache> logger)
    {
        _memoryCache = memoryCache;
        _logger = logger;
    }

    public bool TryGetCachedResponse(IRequest request, [NotNullWhen(true)] out IResponse? response)
    {
        response = null;
        if (request.Questions.Count != 1) return false;
        var key = new QueryCacheKey(request, request.Questions[0]);
        if (_memoryCache.TryGetValue(key, out QueryCacheData? data) && data is not null)
        {
            response = Response.FromArray(data.Payload);
            response.Id = request.Id;
            response.Questions.Clear();
            response.Questions.Add(request.Questions[0]);
            // TODO: Update answers with adjusted TTL
            return true;
        }

        return false;
    }

    public void TryAddCacheEntry(IRequest request, IResponse response)
    {
        if (request.Questions.Count != 1) return;
        using var timeToLivePooledList =
            response.AnswerRecords.Concat(response.AdditionalRecords).Concat(response.AuthorityRecords)
                .Select(i => i.TimeToLive)
                .OrderBy(i => i)
                .ToPooledList();
        if (timeToLivePooledList.Count == 0) return;
        var cacheTimeToLive = timeToLivePooledList.First();
        if (cacheTimeToLive <= TimeSpan.Zero) return;

        var cacheSlidingExpiration =
            TimeSpan.FromSeconds(Math.Floor(Math.Min((cacheTimeToLive / 4).TotalSeconds, 10.0)));
        

        var key = new QueryCacheKey(request, request.Questions[0]);
        var cacheEntry = _memoryCache.CreateEntry(key);
        var cacheData = new QueryCacheData(response);
        cacheEntry.Value = cacheData;
        cacheEntry.AbsoluteExpirationRelativeToNow = cacheTimeToLive;
        if (cacheSlidingExpiration < cacheTimeToLive)
        {
            cacheEntry.SlidingExpiration = cacheSlidingExpiration;
        }
        cacheEntry.Priority = CacheItemPriority.High;
        cacheEntry.RegisterPostEvictionCallback(DnsCacheEntryEvictedCallback);
        cacheEntry.Dispose();
    }

    private void DnsCacheEntryEvictedCallback(object key, object? value, EvictionReason reason, object? state)
    {
        _logger.LogDebug("Cache record {key} evicted, reason {reason}", key, reason);
    }
}