using System.Collections.Immutable;
using System.Net;

using Dhcpr.Dns.Core.Authoritative;
using Dhcpr.Dns.Core.Protocol.RecordData;

using DnsZone;

namespace Dhcpr.Dns.Core.Protocol.Zone;

public static class ZoneFileParser
{
    public static RootZoneSnapshot ParseRootZone(string text, DateTimeOffset? loadedAt = null)
    {
        var at = loadedAt ?? DateTimeOffset.UtcNow;
        var records = Parse(text);
        StartOfAuthorityData? soa = null;
        var soaTtl = TimeSpan.FromSeconds(86400);

        var byOwner = new Dictionary<string, List<DomainResourceRecord>>(StringComparer.OrdinalIgnoreCase);
        foreach (var record in records)
        {
            if (record.Type is DomainRecordType.SOA && record.Data is StartOfAuthorityData soaData)
            {
                soa = soaData;
                soaTtl = record.TimeToLive;
            }

            var key = RootZoneSnapshot.NormalizeOwner(record.Name.ToString());
            if (!byOwner.TryGetValue(key, out var list))
            {
                list = new List<DomainResourceRecord>();
                byOwner[key] = list;
            }

            list.Add(record);
        }

        if (soa is null)
            throw new FormatException("Zone file is missing apex SOA");

        return new RootZoneSnapshot(
            soa,
            soaTtl,
            at,
            byOwner.ToDictionary(
                static kv => kv.Key,
                static kv => kv.Value.ToImmutableArray(),
                StringComparer.OrdinalIgnoreCase));
    }

    /// <summary>Extract A/AAAA tip addresses from a named.root style hints file.</summary>
    public static ImmutableArray<IPAddress> ParseNamedRootAddresses(string text)
    {
        var addresses = new List<IPAddress>();
        foreach (var record in Parse(text))
        {
            if (record.Data is IPAddressData ip)
                addresses.Add(ip.Address);
        }

        return addresses.Distinct().ToImmutableArray();
    }

    public static IReadOnlyList<DomainResourceRecord> Parse(string text, string? origin = null)
    {
        var filtered = BindZoneUnsupportedFilter.Filter(text);
        try
        {
            var zone = DnsZoneFile.Parse(filtered, origin);
            return BindZoneMapper.MapAll(zone.Records);
        }
        catch (Exception ex) when (ex is not FormatException and not OperationCanceledException)
        {
            throw new FormatException($"Failed to parse BIND zone file: {ex.Message}", ex);
        }
    }

    /// <summary>Parse a BIND zone file from disk with <c>$INCLUDE</c> support.</summary>
    public static IReadOnlyList<DomainResourceRecord> ParseFile(string path)
    {
        var source = new BindFileDnsSource(path, BindZoneUnsupportedFilter.Filter);
        try
        {
            var zone = DnsZoneFile.Parse(source);
            return BindZoneMapper.MapAll(zone.Records);
        }
        catch (Exception ex) when (ex is not FormatException and not OperationCanceledException)
        {
            throw new FormatException($"Failed to parse BIND zone file '{path}': {ex.Message}", ex);
        }
    }

    /// <summary>Legacy alias for <see cref="Parse"/>.</summary>
    public static IReadOnlyList<DomainResourceRecord> ParseRecords(string text)
        => Parse(text);
}
