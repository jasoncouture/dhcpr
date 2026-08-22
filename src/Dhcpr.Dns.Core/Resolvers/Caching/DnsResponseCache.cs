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
    private static readonly TimeSpan _negativeCacheTtl = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan _maxCacheTtl = TimeSpan.FromHours(1);

    private readonly IMemoryCache _memoryCache;
    private readonly IDnsCacheEventPublisher _events;

    public DnsResponseCache(IMemoryCache memoryCache, IDnsCacheEventPublisher? events = null)
    {
        _memoryCache = memoryCache;
        _events = events ?? NoOpDnsCacheEventPublisher.Instance;
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

    public void Clear()
    {
        ImportClear();
        _events.PublishClear();
    }

    public void ImportClear() => (_memoryCache as MemoryCache)?.Clear();

    public void Remove(DomainMessage request)
    {
        if (request.Questions.Length != 1)
            return;
        _memoryCache.Remove(DnsCacheKey.FromQuestion(request.Questions[0]));
    }

    public void UpdateSecurityStatus(DomainMessage request, DnssecValidationStatus securityStatus)
    {
        ImportSecurityStatus(request, securityStatus);
        _events.PublishSecurityStatus(request, securityStatus);
    }

    public void ImportSecurityStatus(DomainMessage request, DnssecValidationStatus securityStatus)
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
        var cachedAt = DateTimeOffset.UtcNow;
        if (!TryAccept(request, response, securityStatus, cachedAt, storeGlue: true))
            return;

        _events.PublishSet(request, response, securityStatus, cachedAt);
    }

    public void Import(
        DomainMessage request,
        DomainMessage response,
        DnssecValidationStatus securityStatus,
        DateTimeOffset cachedAt)
        => TryAccept(request, response, securityStatus, cachedAt, storeGlue: true);

    private bool TryAccept(
        DomainMessage request,
        DomainMessage response,
        DnssecValidationStatus securityStatus,
        DateTimeOffset cachedAt,
        bool storeGlue)
    {
        if (request.Questions.Length != 1)
            return false;
        if (response.Flags.Truncated)
            return false;
        if (response.Flags.ResponseCode is DomainResponseCode.ServerFailure or DomainResponseCode.Refused)
            return false;
        if (securityStatus is DnssecValidationStatus.Bogus)
            return false;

        var questionType = request.Questions[0].Type;

        // Referrals (empty ANSWER + NS in AUTHORITY) are not answers. Caching them
        // under QNAME/NS made the later child query replay the TLD referral.
        if (response.Records.Answers.Length == 0 &&
            response.Records.Any(r => r.Type == DomainRecordType.NS) &&
            response.Flags.ResponseCode is DomainResponseCode.NoError)
            return false;

        // Upstream hop types (DNSKEY / DS / NS) cache like any other answer, including RRSIGs.
        // Glue from NS responses is side-cached as A/AAAA with the parent's security status.
        if (!TryStore(request, response, securityStatus, cachedAt))
            return false;

        if (storeGlue && questionType is DomainRecordType.NS)
            CacheGlueRecords(response, securityStatus, cachedAt);

        return true;
    }

    private bool TryStore(
        DomainMessage request,
        DomainMessage response,
        DnssecValidationStatus securityStatus,
        DateTimeOffset cachedAt)
    {
        var lifetime = ComputeLifetime(response);
        if (lifetime <= TimeSpan.Zero)
            return false;

        if (lifetime > _maxCacheTtl)
            lifetime = _maxCacheTtl;

        var age = DateTimeOffset.UtcNow - cachedAt;
        if (age < TimeSpan.Zero)
            age = TimeSpan.Zero;
        lifetime -= age;
        if (lifetime <= TimeSpan.Zero)
            return false;

        var key = DnsCacheKey.FromQuestion(request.Questions[0]);
        // Strip AD — security lives in SecurityStatus only.
        var flags = response.Flags with { Authentic = false };
        var entry = new CacheEntry(flags, response.Records, cachedAt)
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

    private void CacheGlueRecords(
        DomainMessage nsResponse,
        DnssecValidationStatus securityStatus,
        DateTimeOffset cachedAt)
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
            TryStore(glueRequest, glueResponse, securityStatus, cachedAt);
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
            return _negativeCacheTtl;

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

        var builder = ImmutableArray.CreateBuilder<DomainResourceRecord>();
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

        return builder.ToImmutable();
    }

    private sealed class CacheEntry
    {
        public CacheEntry(
            DomainMessageFlags flags,
            DomainResourceRecords records,
            DateTimeOffset cachedAt)
        {
            Flags = flags;
            Records = records;
            CachedAt = cachedAt;
        }

        public DomainMessageFlags Flags { get; }
        public DomainResourceRecords Records { get; }
        public DateTimeOffset CachedAt { get; }
        public DnssecValidationStatus SecurityStatus { get; set; }
    }
}
