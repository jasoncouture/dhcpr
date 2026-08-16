using System.Collections.Immutable;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.RecordData;
using Dhcpr.Dns.Core.Protocol.Zone;

using DnsZone;

namespace Dhcpr.Dns.Core.Authoritative;

public static class AuthoritativeZoneBuilder
{
    public static AuthoritativeZone FromRecords(
        IReadOnlyList<DomainResourceRecord> records,
        string sourcePath)
    {
        DomainResourceRecord? soaRecord = null;
        string? apex = null;

        foreach (var record in records)
        {
            if (record.Type is not DomainRecordType.SOA || record.Data is not StartOfAuthorityData)
                continue;
            soaRecord = record;
            apex = RootZoneSnapshot.NormalizeOwner(record.Name.ToString());
            break;
        }

        if (soaRecord is null || apex is null)
            throw new FormatException($"Zone file '{sourcePath}' is missing apex SOA");

        var apexLabels = apex.Length == 0
            ? Array.Empty<string>()
            : apex.Split('.');

        var root = new LabelTreeNode();
        foreach (var record in records)
        {
            var owner = RootZoneSnapshot.NormalizeOwner(record.Name.ToString());
            if (!IsUnderApex(owner, apex))
                continue;

            var relative = GetRelativeLabels(owner, apexLabels);
            var node = root;
            // Relative walk: right-to-left so parent→child matches DNS (label left of parent).
            for (var i = relative.Length - 1; i >= 0; i--)
                node = node.GetOrAddChild(relative[i]);

            node.Records.Add(record);
            if (record.Type is DomainRecordType.NS && relative.Length > 0)
                node.HasNs = true;
        }

        return new AuthoritativeZone(apex, soaRecord, root.ToImmutable(), sourcePath);
    }

    public static AuthoritativeZone ParseFile(string path)
    {
        var source = new BindFileDnsSource(path, BindZoneUnsupportedFilter.Filter);
        try
        {
            var zoneFile = DnsZoneFile.Parse(source);
            var records = BindZoneMapper.MapAll(zoneFile.Records);
            return FromRecords(records, path);
        }
        catch (Exception ex) when (ex is not FormatException and not OperationCanceledException)
        {
            throw new FormatException($"Failed to parse BIND zone file '{path}': {ex.Message}", ex);
        }
    }

    internal static bool IsUnderApex(string owner, string apex)
    {
        if (owner.Equals(apex, StringComparison.OrdinalIgnoreCase))
            return true;
        if (apex.Length == 0)
            return true;
        return owner.EndsWith($".{apex}", StringComparison.OrdinalIgnoreCase);
    }

    internal static string[] GetRelativeLabels(string owner, string[] apexLabels)
    {
        if (apexLabels.Length == 0)
            return owner.Length == 0 ? [] : owner.Split('.');

        var ownerLabels = owner.Length == 0 ? [] : owner.Split('.');
        if (ownerLabels.Length < apexLabels.Length)
            return [];

        // owner = relative + apex
        var relativeLen = ownerLabels.Length - apexLabels.Length;
        if (relativeLen <= 0)
            return [];

        var relative = new string[relativeLen];
        Array.Copy(ownerLabels, 0, relative, 0, relativeLen);
        return relative;
    }
}
