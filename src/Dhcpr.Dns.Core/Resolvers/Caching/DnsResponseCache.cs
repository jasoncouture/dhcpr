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
        if (HasExpiredTtl(records))
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
        // Never cache bare delegations — they are not answers and poison the cache for hours.
        if (response.Records.Answers.Length == 0 &&
            response.Records.Any(r => r.Type == DomainRecordType.NS) &&
            response.Flags.ResponseCode is DomainResponseCode.NoError)
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
        var min = TimeSpan.MaxValue;
        var found = false;
        foreach (var record in response.Records)
        {
            if (record.TimeToLive <= TimeSpan.Zero)
                continue;
            if (record.TimeToLive >= min)
                continue;
            min = record.TimeToLive;
            found = true;
        }

        if (found)
            return min;

        if (response.Flags.ResponseCode is DomainResponseCode.NameError or DomainResponseCode.NoError)
            return NegativeCacheTtl;

        return TimeSpan.Zero;
    }

    private static bool HasExpiredTtl(DomainResourceRecords records)
    {
        foreach (var record in records)
        {
            if (record.TimeToLive <= TimeSpan.Zero)
                return true;
        }

        return false;
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

        var builder = ImmutableArray.CreateBuilder<DomainResourceRecord>(records.Length);
        foreach (var record in records)
        {
            var ttl = record.TimeToLive - age;
            if (ttl < TimeSpan.Zero)
                ttl = TimeSpan.Zero;
            builder.Add(record with { TimeToLive = ttl });
        }

        return builder.MoveToImmutable();
    }

    private sealed record CacheEntry(
        DomainMessageFlags Flags,
        DomainResourceRecords Records,
        DateTimeOffset Created,
        TimeSpan Lifetime);
}
