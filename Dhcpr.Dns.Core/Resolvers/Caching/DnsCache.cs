using System.Net;

using Dhcpr.Core.Linq;
using Dhcpr.Core.Queue;
using Dhcpr.Data.Dns.Models;

using DNS.Protocol;
using DNS.Protocol.ResourceRecords;

using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;

namespace Dhcpr.Dns.Core.Resolvers.Caching;

public static class ResponseExtensions
{
    public static PooledList<IResourceRecord> ToResourceRecordPooledList(this IResponse response) =>
        response.AnswerRecords
            .Concat(response.AuthorityRecords)
            .Concat(response.AdditionalRecords)
            .ToPooledList();

    public static IResourceRecord Clone(this IResourceRecord resourceRecord, TimeSpan? ttlOverride = null)
    {
        // I really hate this. I am going to eventually write my own library for this server.
        // Or I may fork this package, and submodule it.
        var ttl = ttlOverride ?? resourceRecord.TimeToLive;
        if (ttl < TimeSpan.Zero) ttl = TimeSpan.FromSeconds(0);
        return resourceRecord switch
        {
            CanonicalNameResourceRecord canonicalNameResourceRecord =>
                new CanonicalNameResourceRecord(
                    canonicalNameResourceRecord.Name,
                    canonicalNameResourceRecord.CanonicalDomainName,
                    ttl
                ),
            IPAddressResourceRecord ipAddressResourceRecord =>
                new IPAddressResourceRecord(
                    ipAddressResourceRecord.Name,
                    ipAddressResourceRecord.IPAddress,
                    ttl
                ),
            MailExchangeResourceRecord mailExchangeResourceRecord =>
                new MailExchangeResourceRecord(
                    mailExchangeResourceRecord.Name,
                    mailExchangeResourceRecord.Preference,
                    mailExchangeResourceRecord.ExchangeDomainName,
                    ttl
                ),
            NameServerResourceRecord nameServerResourceRecord =>
                new NameServerResourceRecord(
                    nameServerResourceRecord.Name,
                    nameServerResourceRecord.NSDomainName,
                    ttl
                ),
            PointerResourceRecord pointerResourceRecord =>
                new PointerResourceRecord(
                    IPAddress.Parse(pointerResourceRecord.Name.ToString()!),
                    pointerResourceRecord.PointerDomainName,
                    ttl
                ),
            ServiceResourceRecord serviceResourceRecord =>
                new ServiceResourceRecord(
                    serviceResourceRecord.Name,
                    serviceResourceRecord.Priority,
                    serviceResourceRecord.Weight,
                    serviceResourceRecord.Port,
                    serviceResourceRecord.Target, ttl
                ),
            StartOfAuthorityResourceRecord startOfAuthorityResourceRecord =>
                new StartOfAuthorityResourceRecord(
                    startOfAuthorityResourceRecord.Name,
                    startOfAuthorityResourceRecord.MasterDomainName,
                    startOfAuthorityResourceRecord.ResponsibleDomainName,
                    startOfAuthorityResourceRecord.SerialNumber,
                    startOfAuthorityResourceRecord.RefreshInterval,
                    startOfAuthorityResourceRecord.RetryInterval,
                    startOfAuthorityResourceRecord.ExpireInterval,
                    startOfAuthorityResourceRecord.MinimumTimeToLive,
                    ttl
                ),
            TextResourceRecord textResourceRecord =>
                new TextResourceRecord(
                    textResourceRecord.Name,
                    textResourceRecord.Attribute.Key,
                    textResourceRecord.Attribute.Value,
                    ttl
                ),
            _ => throw new ArgumentOutOfRangeException(nameof(resourceRecord))
        };
    }
}

public sealed class DnsCache : IDnsCache
{
    private readonly IMemoryCache _memoryCache;
    private readonly IMessageQueue<DnsCacheMessage> _cacheMessageQueue;
    private readonly IDnsMemoryCacheWriter _memoryCacheWriter;
    private readonly ILogger<DnsCache> _logger;

    public DnsCache(IMemoryCache memoryCache, IMessageQueue<DnsCacheMessage> cacheMessageQueue,
        IDnsMemoryCacheWriter memoryCacheWriter, ILogger<DnsCache> logger)
    {
        _memoryCache = memoryCache;
        _cacheMessageQueue = cacheMessageQueue;
        _memoryCacheWriter = memoryCacheWriter;
        _logger = logger;
    }

    public IResponse? TryGetCachedResponse(IRequest request)
    {
        if (request.Questions.Count != 1) return null;
        var key = new QueryCacheKey(request.Questions[0]);
        _memoryCache.TryGetValue(key, out QueryCacheData? data);

        if (data is null)
            return null;

        try
        {
            var response = WithUpdatedTimeToLive(data.Response, DateTimeOffset.Now - data.Created);
            using var resourceRecords = response.ToResourceRecordPooledList();
            if (resourceRecords.Any(i => i.TimeToLive <= TimeSpan.Zero))
                DeleteCacheEntry(key);

            response.Id = request.Id;
            return response;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(
                ex,
                "Deleting cache entry {key} because an exception occurred while updating the TTL",
                key
            );
            DeleteCacheEntry(key);
            return null;
        }
    }

    private void DeleteCacheEntry(QueryCacheKey key)
    {
        _memoryCache.Remove(key);
        _cacheMessageQueue.Enqueue(new DnsCacheMessage(key, null, default, true), CancellationToken.None);
    }

    private IResponse WithUpdatedTimeToLive(IResponse response, TimeSpan currentAge)
    {
        using var additionalRecords = response.AdditionalRecords.ToPooledList();
        using var answerRecords = response.AnswerRecords.ToPooledList();
        using var authorityRecords = response.AuthorityRecords.ToPooledList();
        response = response.Clone();
        response.AnswerRecords.Clear();
        response.AdditionalRecords.Clear();
        response.AuthorityRecords.Clear();

        foreach (var item in answerRecords)
            response.AnswerRecords.Add(item.Clone(item.TimeToLive - currentAge));

        foreach (var item in additionalRecords)
            response.AnswerRecords.Add(item.Clone(item.TimeToLive - currentAge));

        foreach (var item in authorityRecords)
            response.AnswerRecords.Add(item.Clone(item.TimeToLive - currentAge));

        return response;
    }



    public void TryAddCacheEntry(IRequest request, IResponse? response)
    {
        if (request.OperationCode != OperationCode.Query)
            return;
        if (response is null or NoCacheResponse or not { Questions.Count: 1 })
            return;
        using var pooledRecords = response.ToResourceRecordPooledList();

        if (pooledRecords.Count > 0 && pooledRecords.All(i => i.Type != request.Questions[0].Type))
            return;

        using var timeToLivePooledList =
            pooledRecords
                .Select(i => i.TimeToLive)
                .OrderBy(i => i)
                .ToPooledList();
        if (timeToLivePooledList.Count == 0)
        {
            timeToLivePooledList.Add(TimeSpan.FromSeconds(60));
        }

        var cacheTimeToLive = timeToLivePooledList.First();
        if (cacheTimeToLive <= TimeSpan.Zero) return;
        var key = new QueryCacheKey(request.Questions[0]);
        _memoryCacheWriter.AddToMemoryCache(key, response, cacheTimeToLive);
        _cacheMessageQueue.Enqueue(new DnsCacheMessage(key, response, cacheTimeToLive, false));
    }
}