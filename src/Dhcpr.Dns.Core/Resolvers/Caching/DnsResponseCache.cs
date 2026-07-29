using System.Collections.Immutable;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Protocol.RecordData;

using Microsoft.Extensions.Caching.Memory;

namespace Dhcpr.Dns.Core.Resolvers.Caching;

/// <summary>
/// Response cache for recursive resolution. Retains full RRsets including RRSIGs.
/// Stores <see cref="DnssecValidationStatus"/> separately from wire flags — never
/// serves AD from a cached <see cref="DomainMessageFlags.Authentic"/> bit.
/// </summary>
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
        => TryGet(request, out response, out _);

    public bool TryGet(DomainMessage request, out DomainMessage? response, out DnssecValidationStatus securityStatus)
    {
        response = null;
        securityStatus = DnssecValidationStatus.Unchecked;
        if (request.Questions.Length != 1)
            return false;

        var key = DnsCacheKey.FromQuestion(request.Questions[0]);
        if (!_memoryCache.TryGetValue(key, out CacheEntry? entry) || entry is null)
            return false;

        var age = DateTimeOffset.UtcNow - entry.CachedAt;
        if (age < TimeSpan.Zero)
            age = TimeSpan.Zero;

        securityStatus = entry.SecurityStatus;
        // Never resurrect AD from cache flags — Dnssec middleware applies AD from status.
        response = new DomainMessage(
            request.Id,
            entry.Flags with
            {
                Response = true,
                RecursionDesired = request.Flags.RecursionDesired,
                RecursionAvailable = true,
                Truncated = false,
                Authentic = false
            },
            request.Questions,
            AgeRecords(entry.Records, age));
        return true;
    }

    public void Clear() => (_memoryCache as MemoryCache)?.Clear();

    public void Remove(DomainMessage request)
    {
        if (request.Questions.Length != 1)
            return;
        _memoryCache.Remove(DnsCacheKey.FromQuestion(request.Questions[0]));
    }

    public void UpdateSecurityStatus(DomainMessage request, DnssecValidationStatus securityStatus)
    {
        if (request.Questions.Length != 1)
            return;

        var key = DnsCacheKey.FromQuestion(request.Questions[0]);
        if (!_memoryCache.TryGetValue(key, out CacheEntry? entry) || entry is null)
            return;

        if (securityStatus is DnssecValidationStatus.Bogus)
        {
            _memoryCache.Remove(key);
            return;
        }

        entry.SecurityStatus = securityStatus;
    }

    public void Set(
        DomainMessage request,
        DomainMessage response,
        DnssecValidationStatus securityStatus = DnssecValidationStatus.Unchecked)
    {
        if (request.Questions.Length != 1)
            return;
        if (response.Flags.Truncated)
            return;
        if (response.Flags.ResponseCode is DomainResponseCode.ServerFailure or DomainResponseCode.Refused)
            return;
        if (securityStatus is DnssecValidationStatus.Bogus)
            return;

        var questionType = request.Questions[0].Type;

        // Bare NS referrals must not be cached as answers for A/AAAA/etc.
        // NS questions may cache delegations — that is the layer answer.
        if (questionType is not DomainRecordType.NS &&
            response.Records.Answers.Length == 0 &&
            response.Records.Any(r => r.Type == DomainRecordType.NS) &&
            response.Flags.ResponseCode is DomainResponseCode.NoError)
            return;

        // Upstream hop types (DNSKEY / DS / NS) cache like any other answer, including RRSIGs.
        // Glue from NS responses is side-cached as A/AAAA with the parent's security status.
        if (!TryStore(request, response, securityStatus))
            return;

        if (questionType is DomainRecordType.NS)
            CacheGlueRecords(response, securityStatus);
    }

    private bool TryStore(
        DomainMessage request,
        DomainMessage response,
        DnssecValidationStatus securityStatus)
    {
        var lifetime = ComputeLifetime(response);
        if (lifetime <= TimeSpan.Zero)
            return false;

        if (lifetime > MaxCacheTtl)
            lifetime = MaxCacheTtl;

        var key = DnsCacheKey.FromQuestion(request.Questions[0]);
        // Strip AD — security lives in SecurityStatus only.
        var flags = response.Flags with { Authentic = false };
        var entry = new CacheEntry(flags, response.Records, DateTimeOffset.UtcNow)
        {
            SecurityStatus = securityStatus
        };

        _memoryCache.Set(key, entry, new MemoryCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = lifetime,
            SlidingExpiration = lifetime / 4,
            Size = 1
        });
        return true;
    }

    private void CacheGlueRecords(DomainMessage nsResponse, DnssecValidationStatus securityStatus)
    {
        var nsNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var record in nsResponse.Records)
        {
            if (record.Type is not DomainRecordType.NS)
                continue;
            if (record.Data is not NameData nameData)
                continue;
            nsNames.Add(nameData.Name.ToString());
        }

        if (nsNames.Count == 0)
            return;

        foreach (var group in nsResponse.Records
                     .Where(r => r.Type is DomainRecordType.A or DomainRecordType.AAAA)
                     .Where(r => nsNames.Contains(r.Name.ToString()))
                     .GroupBy(r => (Name: r.Name, r.Type)))
        {
            var glueRequest = DomainMessage.CreateRequest(group.Key.Name, group.Key.Type);
            var glueRecords = group.ToImmutableArray();
            var glueResponse = new DomainMessage(
                glueRequest.Id,
                nsResponse.Flags with
                {
                    Response = true,
                    ResponseCode = DomainResponseCode.NoError,
                    Authentic = false
                },
                glueRequest.Questions,
                new DomainResourceRecords(
                    glueRecords,
                    ImmutableArray<DomainResourceRecord>.Empty,
                    ImmutableArray<DomainResourceRecord>.Empty));
            TryStore(glueRequest, glueResponse, securityStatus);
        }
    }

    private static TimeSpan ComputeLifetime(DomainMessage response)
    {
        var min = TimeSpan.MaxValue;
        var found = false;
        foreach (var record in response.Records)
        {
            if (record.Type == DomainRecordType.OPT)
                continue;

            if (record.TimeToLive <= TimeSpan.Zero)
                return TimeSpan.Zero;

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

        if (age <= TimeSpan.Zero)
            return records;

        var builder = ImmutableArray.CreateBuilder<DomainResourceRecord>(records.Length);
        foreach (var record in records)
        {
            if (record.Type == DomainRecordType.OPT)
            {
                builder.Add(record);
                continue;
            }

            var ttl = record.TimeToLive - age;
            if (ttl < TimeSpan.Zero)
                ttl = TimeSpan.Zero;
            builder.Add(record with { TimeToLive = ttl });
        }

        return builder.MoveToImmutable();
    }

    private sealed class CacheEntry(
        DomainMessageFlags Flags,
        DomainResourceRecords Records,
        DateTimeOffset CachedAt)
    {
        public DomainMessageFlags Flags { get; } = Flags;
        public DomainResourceRecords Records { get; } = Records;
        public DateTimeOffset CachedAt { get; } = CachedAt;
        public DnssecValidationStatus SecurityStatus { get; set; }
    }
}
