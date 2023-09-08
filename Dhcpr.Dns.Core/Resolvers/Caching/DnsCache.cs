using System.Data;
using System.Diagnostics.CodeAnalysis;

using Dhcpr.Core.Linq;
using Dhcpr.Data;
using Dhcpr.Data.Dns.Models;

using DNS.Protocol;
using DNS.Protocol.ResourceRecords;

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;

namespace Dhcpr.Dns.Core.Resolvers.Caching;

public sealed class DnsCache : IDnsCache
{
    private readonly IMemoryCache _memoryCache;
    private readonly IDataContext _dataContext;
    private readonly ILogger<DnsCache> _logger;
    private readonly SemaphoreSlim _dbLock = new(1, 1);

    public DnsCache(IMemoryCache memoryCache, IDataContext dataContext, ILogger<DnsCache> logger)
    {
        _memoryCache = memoryCache;
        _dataContext = dataContext;
        _logger = logger;
    }

    public async ValueTask<IResponse?> TryGetCachedResponseAsync(IRequest request,
        CancellationToken cancellationToken)
    {
        IResponse? response = null;
        if (request.Questions.Count != 1) return null;
        var key = new QueryCacheKey(request, request.Questions[0]);
        _memoryCache.TryGetValue(key, out QueryCacheData? data);
        if (data is null)
        {
            data = await TryGetDatabaseCachedDnsRecordAsync(key, cancellationToken).ConfigureAwait(false);
            if (data is not null)
            {
                await TryAddCacheEntryAsync(request, data.Response, addToDatabase: false, cancellationToken)
                    .ConfigureAwait(false);
            }
        }

        if (data is null)
            return null;

        try
        {
            response = WithUpdatedTimeToLive(data.Response, DateTimeOffset.Now - data.Created);
            if (
                response.AuthorityRecords.Any(i => i.TimeToLive <= TimeSpan.Zero) ||
                response.AnswerRecords.Any(i => i.TimeToLive <= TimeSpan.Zero) ||
                response.AdditionalRecords.Any(i => i.TimeToLive <= TimeSpan.Zero)
            )
            {
                // This is expired, but somehow still in cache. Evict it and lie that we didn't find it.
                await DeleteCacheEntryAsync(key, cancellationToken).ConfigureAwait(false);
            }
            else
            {
                response.Id = request.Id;
                return response;
            }
        }
        catch
        {
            await DeleteCacheEntryAsync(key, cancellationToken).ConfigureAwait(false);
            return null;
        }

        return null;
    }

    private async Task DeleteCacheEntryAsync(QueryCacheKey key, CancellationToken cancellationToken)
    {
        await _dbLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            
            await using var transaction = await _dataContext
                .BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken).ConfigureAwait(false);
            await _dataContext.CacheEntries.Where(i =>
                    i.Name == key.Domain &&
                    i.Type == (ResourceRecordType)key.Type &&
                    i.Class == (ResourceRecordClass)key.Class
                )
                .ExecuteDeleteAsync(cancellationToken).ConfigureAwait(false);
            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);

            _memoryCache.Remove(key);
        }
        catch
        {
            _dbLock.Release();
            // Ignored.
        }
    }

    private async Task<QueryCacheData?> TryGetDatabaseCachedDnsRecordAsync(QueryCacheKey key,
        CancellationToken cancellationToken)
    {
        var name = key.Domain;
        var type = (ResourceRecordType)key.Type;
        var @class = (ResourceRecordClass)key.Class;
        await _dbLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await using var transaction = await
                _dataContext.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken)
                    .ConfigureAwait(false);

            var result = await _dataContext.CacheEntries.AsNoTracking()
                .Where(i => i.Name == name && i.Type == type && i.Class == @class)
                .SingleOrDefaultAsync(cancellationToken: cancellationToken)
                .ConfigureAwait(false);

            if (result is null) return null;

            if (result.Expires <= DateTimeOffset.Now)
            {
                await _dataContext.CacheEntries.Where(i => i.Id == result.Id).ExecuteDeleteAsync(cancellationToken)
                    .ConfigureAwait(false);
                await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
                return null;
            }

            return new QueryCacheData(Response.FromArray(result.Payload), result.Created, result.TimeToLive);
        }
        catch
        {
            return null;
        }
        finally
        {
            _dbLock.Release();
        }
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
        var recordBytes = new ResourceRecord(resourceRecord.Name, resourceRecord.Data, resourceRecord.Type,
            resourceRecord.Class, ttl).ToArray();
        return ResourceRecordFactory.FromArray(recordBytes, 0);
    }

    public ValueTask TryAddCacheEntryAsync(IRequest request, IResponse response, CancellationToken cancellationToken)
        => TryAddCacheEntryAsync(request, response, true, cancellationToken);

    public async ValueTask TryAddCacheEntryAsync(IRequest request, IResponse response, bool addToDatabase,
        CancellationToken cancellationToken)
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
        if (addToDatabase)
        {
            await _dbLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var name = request.Questions[0].Name.ToString()!.ToLower();
                var @class = (ResourceRecordClass)request.Questions[0].Class;
                var type = (ResourceRecordType)request.Questions[0].Type;
                await using var transaction = await _dataContext
                    .BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken).ConfigureAwait(false);
                if (!await _dataContext.CacheEntries.AnyAsync(
                        i => i.Name == name && i.Type == type && i.Class == @class,
                        cancellationToken: cancellationToken).ConfigureAwait(false))
                {
                    var dbCacheEntry = new DnsCacheEntry()
                    {
                        Name = name,
                        TimeToLive = cacheTimeToLive,
                        Class = @class,
                        Type = type,
                        Payload = request.ToArray(),
                        Expires = DateTimeOffset.Now.Add(cacheTimeToLive)
                    };

                    _dataContext.CacheEntries.Add(dbCacheEntry);
                    await _dataContext.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
                    await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
                }
            }
            catch
            {
                // Ignored.
            }
            finally
            {
                _dbLock.Release();
            }
        }

        var cacheSlidingExpiration =
            TimeSpan.FromSeconds(Math.Floor(Math.Max((cacheTimeToLive / 4).TotalSeconds, 10.0)));


        var key = new QueryCacheKey(request, request.Questions[0]);
        var cacheEntry = _memoryCache.CreateEntry(key);
        var cacheData = new QueryCacheData(response, cacheTimeToLive);
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