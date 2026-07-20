using System.Collections.Immutable;

using Dhcpr.Dns.Core.Protocol;

using Microsoft.Extensions.Caching.Memory;

namespace Dhcpr.Dns.Core.Resolvers.Caching;

public sealed class DnsResponseCache : IDnsResponseCache
{
    private static readonly TimeSpan NegativeCacheTtl = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan MaxCacheTtl = TimeSpan.FromHours(1);

    private readonly IMemoryCache _memoryCache;

    public DnsResponseCache(IMemoryCache memoryCache)
    {
        _memoryCache = memoryCache;
    }

    public bool TryGet(DomainMessage request, out DomainMessage? response)
    {
        response = null;
        if (request.Questions.Length != 1)
            return false;

        var key = DnsCacheKey.FromQuestion(request.Questions[0]);
        if (!_memoryCache.TryGetValue(key, out CacheEntry? entry) || entry is null)
            return false;

        var age = DateTimeOffset.UtcNow - entry.Created;
        if (age >= entry.Lifetime)
        {
            _memoryCache.Remove(key);
            return false;
        }

        var records = AgeRecords(entry.Records, age);
        if (records.Any(r => r.TimeToLive <= TimeSpan.Zero))
        {
            _memoryCache.Remove(key);
            return false;
        }

        response = new DomainMessage(
            request.Id,
            entry.Flags with
            {
                Response = true,
                RecursionDesired = request.Flags.RecursionDesired,
                RecursionAvailable = true,
                Truncated = false
            },
            request.Questions,
            records);
        return true;
    }

    public void Set(DomainMessage request, DomainMessage response)
    {
        if (request.Questions.Length != 1)
            return;
        if (response.Flags.Truncated)
            return;
        if (response.Flags.ResponseCode is DomainResponseCode.ServerFailure or DomainResponseCode.Refused)
            return;

        var lifetime = ComputeLifetime(response);
        if (lifetime <= TimeSpan.Zero)
            return;

        if (lifetime > MaxCacheTtl)
            lifetime = MaxCacheTtl;

        var key = DnsCacheKey.FromQuestion(request.Questions[0]);
        var entry = new CacheEntry(
            response.Flags,
            response.Records,
            DateTimeOffset.UtcNow,
            lifetime);

        _memoryCache.Set(key, entry, new MemoryCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = lifetime,
            Size = 1
        });
    }

    private static TimeSpan ComputeLifetime(DomainMessage response)
    {
        var ttls = response.Records
            .Select(r => r.TimeToLive)
            .Where(t => t > TimeSpan.Zero)
            .ToArray();

        if (ttls.Length > 0)
            return ttls.Min();

        // NXDOMAIN / NODATA with no usable TTL — short negative cache.
        if (response.Flags.ResponseCode is DomainResponseCode.NameError or DomainResponseCode.NoError)
            return NegativeCacheTtl;

        return TimeSpan.Zero;
    }

    private static DomainResourceRecords AgeRecords(DomainResourceRecords records, TimeSpan age)
        => new(
            AgeSection(records.Answers, age),
            AgeSection(records.Authorities, age),
            AgeSection(records.Additional, age));

    private static ImmutableArray<DomainResourceRecord> AgeSection(
        ImmutableArray<DomainResourceRecord> records,
        TimeSpan age)
    {
        if (records.IsDefaultOrEmpty)
            return records;

        return records.Select(r =>
        {
            var ttl = r.TimeToLive - age;
            if (ttl < TimeSpan.Zero)
                ttl = TimeSpan.Zero;
            return r with { TimeToLive = ttl };
        }).ToImmutableArray();
    }

    private sealed record CacheEntry(
        DomainMessageFlags Flags,
        DomainResourceRecords Records,
        DateTimeOffset Created,
        TimeSpan Lifetime);
}
