using System.Diagnostics.CodeAnalysis;

using Dhcpr.Core.Linq;

using DNS.Protocol;
using DNS.Protocol.ResourceRecords;

using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;

namespace Dhcpr.Dns.Core.Resolvers.Caching;

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
            response = WithUpdatedTimeToLive(data.Response, DateTimeOffset.Now - data.Created);
            if (
                response.AuthorityRecords.Any(i => i.TimeToLive <= TimeSpan.Zero) ||
                response.AnswerRecords.Any(i => i.TimeToLive <= TimeSpan.Zero) ||
                response.AdditionalRecords.Any(i => i.TimeToLive <= TimeSpan.Zero)
                )
            {
                // This is expired, but somehow still in cache. Evict it and lie that we didn't find it.
                _memoryCache.Remove(key);
                return false;
            }
            response.Id = request.Id;
            return true;
        }

        return false;
    }

    private IResponse WithUpdatedTimeToLive(IResponse response, TimeSpan currentAge)
    {
        using var additionalRecords = response.AdditionalRecords.ToPooledList();
        using var answerRecords = response.AnswerRecords.ToPooledList();
        using var authorityRecords = response.AuthorityRecords.ToPooledList();
        response = new Response(response);
        response.AnswerRecords.Clear();
        response.AdditionalRecords.Clear();
        response.AuthorityRecords.Clear();

        foreach (var item in answerRecords)
            response.AnswerRecords.Add(WithUpdatedTimeToLive(item, currentAge));

        foreach (var item in additionalRecords)
            response.AdditionalRecords.Add(WithUpdatedTimeToLive(item, currentAge));

        foreach (var item in authorityRecords)
            response.AuthorityRecords.Add(WithUpdatedTimeToLive(item, currentAge));

        return response;
    }

    private IResourceRecord WithUpdatedTimeToLive(IResourceRecord resourceRecord, TimeSpan currentAge)
    {
        var ttl = resourceRecord.TimeToLive - currentAge;
        if (ttl < TimeSpan.Zero) ttl = TimeSpan.FromSeconds(0);
        // We re-create this this way, because something may want to use a specific record type to detect things
        // And we don't want to break that.
        var recordBytes = new ResourceRecord(resourceRecord.Name, resourceRecord.Data, resourceRecord.Type, resourceRecord.Class, ttl).ToArray();
        return ResourceRecordFactory.FromArray(recordBytes, 0);
    }

    public void TryAddCacheEntry(IRequest request, IResponse response)
    {
        if (response is NoCacheResponse) return;
        if (request.Questions.Count != 1) return;
        if (request.Questions[0].Type is RecordType.A or RecordType.AAAA &&
            response.ResponseCode == ResponseCode.NoError && response.AnswerRecords.Count == 0)
        {
            return;
        }

        using var timeToLivePooledList =
            response.AnswerRecords.Concat(response.AdditionalRecords).Concat(response.AuthorityRecords)
                .Select(i => i.TimeToLive)
                .OrderBy(i => i)
                .ToPooledList();
        if (timeToLivePooledList.Count == 0)
        {
            timeToLivePooledList.Add(TimeSpan.FromMinutes(1));
        }

        var cacheTimeToLive = timeToLivePooledList.First();
        if (cacheTimeToLive <= TimeSpan.Zero) return;

        var cacheSlidingExpiration =
            TimeSpan.FromSeconds(Math.Floor(Math.Max((cacheTimeToLive / 4).TotalSeconds, 10.0)));


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