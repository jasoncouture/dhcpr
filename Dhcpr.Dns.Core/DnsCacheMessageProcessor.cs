using System.Data;
using System.Diagnostics;

using Dhcpr.Core.Queue;
using Dhcpr.Data;
using Dhcpr.Data.Dns.Models;
using Dhcpr.Dns.Core.Resolvers.Caching;

using DNS.Protocol;

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace Dhcpr.Dns.Core;

public sealed class DnsCacheMessageProcessor : IQueueMessageProcessor<DnsCacheMessage>
{
    private readonly IDataContext _context;
    private readonly ILogger<DnsCacheMessageProcessor> _logger;

    public DnsCacheMessageProcessor(IDataContext context, ILogger<DnsCacheMessageProcessor> logger)
    {
        _context = context;
        _logger = logger;
    }

    public async Task ProcessMessageAsync(DnsCacheMessage message, CancellationToken cancellationToken)
    {
        var (key, response, timeToLive, invalidate) = message;
        if (response is null && !invalidate) return;
        // Try 2 times, then give up.
        for (var x = 0; x < 2; x++)
        {
            try
            {
                if (invalidate)
                {
                    await RemoveFromDatabaseAsync(key, cancellationToken);
                    _logger.LogInformation("Deleted {key} from dns cache", key);
                    return;
                }

                Debug.Assert(response is not null, "response is not null");
                await AddToDatabaseAsync(key, response, timeToLive, cancellationToken);
                _logger.LogInformation("Added {key} to dns cache", key);
                return;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to add data to cache due to an exception");
            }
        }
    }


    private async Task AddToDatabaseAsync(
        QueryCacheKey key,
        IResponse response,
        TimeSpan timeToLive,
        CancellationToken cancellationToken
    )
    {
        if (timeToLive <= TimeSpan.FromSeconds(1))
            return;
        key = key with { Domain = key.Domain.ToLower() };
        
        await using var transaction = await _context
            .BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken)
            ;

        var existingRecord = await _context.FindCacheEntryAsync(key, cancellationToken)
            ;

        existingRecord ??= _context.CacheEntries.Add(new DnsCacheEntry()
        {
            Class = (ResourceRecordClass)key.Class, Type = (ResourceRecordType)key.Type, Name = key.Domain
        }).Entity;
        existingRecord.TimeToLive = timeToLive;
        existingRecord.Expires = DateTimeOffset.Now.Add(timeToLive);
        existingRecord.Payload = response.ToArray();

        await _context.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
    }

    private async Task RemoveFromDatabaseAsync(QueryCacheKey key, CancellationToken cancellationToken)
    {
        await using var transaction = await _context
            .BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken)
            ;
        await _context.RemoveCacheEntryAsync(key, cancellationToken)
            ;
        await transaction.CommitAsync(cancellationToken)
            ;
    }
}

public static class DataContextExtensions
{
    public static async Task RemoveCacheEntryAsync(this IDataContext context, QueryCacheKey key,
        CancellationToken cancellationToken)
    {
        await RemoveCacheEntryAsync(context, key.Domain, key.Type, key.Class, cancellationToken)
            ;
    }

    public static async Task RemoveCacheEntryAsync(this IDataContext context, string name, RecordType type,
        RecordClass @class, CancellationToken cancellationToken = default)
    {
        var recordType = (ResourceRecordType)type;
        var recordClass = (ResourceRecordClass)@class;
        await context.CacheEntries
            .Where(i => i.Name == name && i.Type == recordType && i.Class == recordClass)
            .ExecuteDeleteAsync(cancellationToken)
            ;
    }

    public static async Task<DnsCacheEntry?> FindCacheEntryAsync(this IDataContext context, QueryCacheKey key,
        CancellationToken cancellationToken)
    {
        return await FindCacheEntryAsync(context, key.Domain.ToLower(), key.Type, key.Class, cancellationToken)
            ;
    }

    public static IResponse? ToResponse(this DnsCacheEntry? entry)
    {
        if (entry is null) return null;
        try
        {
            return Response.FromArray(entry.Payload);
        }
        catch
        {
            return null;
        }
    }

    public static async Task<DnsCacheEntry?> FindCacheEntryAsync(this IDataContext context, string name,
        RecordType type, RecordClass @class, CancellationToken cancellationToken)
    {
        var recordType = (ResourceRecordType)type;
        var recordClass = (ResourceRecordClass)@class;
        return await context.CacheEntries
            .Where(i => i.Name == name && i.Type == recordType && i.Class == recordClass)
            .SingleOrDefaultAsync(cancellationToken: cancellationToken)
            ;
    }
}