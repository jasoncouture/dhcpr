using Dhcpr.Data;
using Dhcpr.Data.Dns.Models;
using Dhcpr.Dns.Core.Resolvers.Caching;

using DNS.Protocol;

using Microsoft.EntityFrameworkCore;

namespace Dhcpr.Dns.Core;

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