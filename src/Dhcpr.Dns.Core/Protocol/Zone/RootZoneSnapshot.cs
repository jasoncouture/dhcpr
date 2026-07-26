using System.Collections.Immutable;

using Dhcpr.Dns.Core.Protocol.RecordData;

namespace Dhcpr.Dns.Core.Protocol.Zone;

public sealed class RootZoneSnapshot
{
    public RootZoneSnapshot(
        StartOfAuthorityData soa,
        TimeSpan soaTtl,
        DateTimeOffset loadedAt,
        IReadOnlyDictionary<string, ImmutableArray<DomainResourceRecord>> recordsByOwner)
    {
        Soa = soa;
        SoaTtl = soaTtl;
        LoadedAt = loadedAt;
        RecordsByOwner = recordsByOwner;
    }

    public StartOfAuthorityData Soa { get; }
    public TimeSpan SoaTtl { get; }
    public DateTimeOffset LoadedAt { get; }
    public IReadOnlyDictionary<string, ImmutableArray<DomainResourceRecord>> RecordsByOwner { get; }

    public DateTimeOffset ExpiresAt => LoadedAt + Soa.ExpireInterval;

    public bool IsExpired(DateTimeOffset utcNow) => utcNow >= ExpiresAt;

    public bool TryGetRecords(string owner, out ImmutableArray<DomainResourceRecord> records)
        => RecordsByOwner.TryGetValue(NormalizeOwner(owner), out records);

    public static string NormalizeOwner(string owner)
    {
        owner = owner.Trim().TrimEnd('.');
        return owner.Length == 0 ? string.Empty : owner.ToLowerInvariant();
    }
}
