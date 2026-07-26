using System.Collections.Immutable;
using System.Globalization;
using System.Net;
using System.Text;

using Dhcpr.Dns.Core.Protocol.RecordData;

namespace Dhcpr.Dns.Core.Protocol.Zone;

public static class ZoneFileParser
{
    private static readonly HashSet<string> IgnoredTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        "RRSIG", "NSEC", "NSEC3", "DNSKEY", "ZONEMD", "NSEC3PARAM", "CDS", "CDNSKEY", "TYPE65534"
    };

    public static RootZoneSnapshot ParseRootZone(string text, DateTimeOffset? loadedAt = null)
    {
        var at = loadedAt ?? DateTimeOffset.UtcNow;
        var records = ParseRecords(text);
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
        foreach (var record in ParseRecords(text))
        {
            if (record.Data is IPAddressData ip)
                addresses.Add(ip.Address);
        }

        return addresses.Distinct().ToImmutableArray();
    }

    public static IReadOnlyList<DomainResourceRecord> ParseRecords(string text)
    {
        var expanded = ExpandParentheses(StripComments(text));
        var origin = DomainLabels.Empty;
        var defaultTtl = TimeSpan.FromSeconds(3600);
        var records = new List<DomainResourceRecord>();
        DomainLabels? lastOwner = null;

        foreach (var rawLine in expanded.Split('\n'))
        {
            if (rawLine.Length == 0 || IsBlank(rawLine))
                continue;

            var blankOwner = char.IsWhiteSpace(rawLine[0]);
            var line = rawLine.Trim();
            if (line.Length == 0)
                continue;

            if (line.StartsWith("$ORIGIN", StringComparison.OrdinalIgnoreCase))
            {
                var originName = line["$ORIGIN".Length..].Trim().TrimEnd('.');
                origin = string.IsNullOrEmpty(originName)
                    ? DomainLabels.Empty
                    : new DomainLabels(originName);
                continue;
            }

            if (line.StartsWith("$TTL", StringComparison.OrdinalIgnoreCase))
            {
                if (TryParseTtl(line["$TTL".Length..].Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries)[0], out var ttl))
                    defaultTtl = ttl;
                continue;
            }

            if (line.StartsWith('$'))
                continue;

            if (!TryParseRecordLine(line, origin, defaultTtl, blankOwner, ref lastOwner, out var record) ||
                record is null)
                continue;

            records.Add(record);
        }

        return records;
    }

    private static bool IsBlank(string line)
    {
        foreach (var ch in line)
        {
            if (!char.IsWhiteSpace(ch))
                return false;
        }

        return true;
    }

    private static bool TryParseRecordLine(
        string line,
        DomainLabels origin,
        TimeSpan defaultTtl,
        bool blankOwner,
        ref DomainLabels? lastOwner,
        out DomainResourceRecord? record)
    {
        record = null;
        var tokens = Tokenize(line);
        if (tokens.Count < (blankOwner ? 2 : 3))
            return false;

        var index = 0;
        DomainLabels owner;
        if (blankOwner)
        {
            if (lastOwner is null)
                return false;
            owner = lastOwner;
        }
        else
        {
            owner = ResolveOwner(tokens[0], origin);
            lastOwner = owner;
            index++;
        }

        var ttl = defaultTtl;
        if (index < tokens.Count && TryParseTtl(tokens[index], out var parsedTtl))
        {
            ttl = parsedTtl;
            index++;
        }

        if (index < tokens.Count && tokens[index].Equals("IN", StringComparison.OrdinalIgnoreCase))
            index++;

        if (index >= tokens.Count)
            return false;

        var typeToken = tokens[index++];
        if (IgnoredTypes.Contains(typeToken))
            return false;

        if (!TryParseType(typeToken, out var type))
            return false;

        var rdata = tokens.Skip(index).ToArray();
        if (!TryParseRdata(type, rdata, origin, out var data) || data is null)
            return false;

        record = new DomainResourceRecord(owner, type, DomainRecordClass.IN, ttl, data);
        return true;
    }

    private static DomainLabels ResolveOwner(string token, DomainLabels origin)
    {
        if (token is "@")
            return origin;
        if (token is ".")
            return DomainLabels.Empty;

        var absolute = token.EndsWith('.');
        var name = token.TrimEnd('.');
        if (string.IsNullOrEmpty(name))
            return DomainLabels.Empty;

        if (absolute || origin.Count == 0)
            return new DomainLabels(name);

        var labels = name.Split('.', StringSplitOptions.RemoveEmptyEntries)
            .Concat(origin.Labels.Select(static l => l.Label));
        return new DomainLabels(labels);
    }

    private static bool TryParseRdata(
        DomainRecordType type,
        string[] rdata,
        DomainLabels origin,
        out IDomainResourceRecordData? data)
    {
        data = null;
        switch (type)
        {
            case DomainRecordType.NS:
                if (rdata.Length < 1)
                    return false;
                data = new NameData(ResolveOwner(rdata[0], origin));
                return true;

            case DomainRecordType.A:
                if (rdata.Length < 1 || !IPAddress.TryParse(rdata[0], out var v4) ||
                    v4.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                    return false;
                data = new IPAddressData(v4);
                return true;

            case DomainRecordType.AAAA:
                if (rdata.Length < 1 || !IPAddress.TryParse(rdata[0], out var v6) ||
                    v6.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6)
                    return false;
                data = new IPAddressData(v6);
                return true;

            case DomainRecordType.SOA:
                if (rdata.Length < 7)
                    return false;
                data = new StartOfAuthorityData(
                    ResolveOwner(rdata[0], origin),
                    ResolveOwner(rdata[1], origin),
                    int.Parse(rdata[2], CultureInfo.InvariantCulture),
                    TimeSpan.FromSeconds(long.Parse(rdata[3], CultureInfo.InvariantCulture)),
                    TimeSpan.FromSeconds(long.Parse(rdata[4], CultureInfo.InvariantCulture)),
                    TimeSpan.FromSeconds(long.Parse(rdata[5], CultureInfo.InvariantCulture)),
                    TimeSpan.FromSeconds(long.Parse(rdata[6], CultureInfo.InvariantCulture)));
                return true;

            case DomainRecordType.DS:
                if (rdata.Length < 4)
                    return false;
                var keyTag = ushort.Parse(rdata[0], CultureInfo.InvariantCulture);
                var algorithm = (DnssecAlgorithmType)byte.Parse(rdata[1], CultureInfo.InvariantCulture);
                var digestType = (DelegationSignerDigestType)byte.Parse(rdata[2], CultureInfo.InvariantCulture);
                var hex = string.Concat(rdata.Skip(3));
                data = new DelegationSignerData(keyTag, algorithm, digestType, Convert.FromHexString(hex).ToImmutableArray());
                return true;

            default:
                return false;
        }
    }

    private static bool TryParseType(string token, out DomainRecordType type)
    {
        type = default;
        if (!Enum.TryParse(token, ignoreCase: true, out DomainRecordType parsed))
            return false;
        type = parsed;
        return Enum.IsDefined(parsed);
    }

    private static bool TryParseTtl(string token, out TimeSpan ttl)
    {
        ttl = default;
        if (!long.TryParse(token, NumberStyles.Integer, CultureInfo.InvariantCulture, out var seconds) || seconds < 0)
            return false;
        ttl = TimeSpan.FromSeconds(seconds);
        return true;
    }

    private static List<string> Tokenize(string line)
    {
        var tokens = new List<string>();
        var current = new StringBuilder();
        foreach (var ch in line)
        {
            if (char.IsWhiteSpace(ch))
            {
                if (current.Length > 0)
                {
                    tokens.Add(current.ToString());
                    current.Clear();
                }

                continue;
            }

            current.Append(ch);
        }

        if (current.Length > 0)
            tokens.Add(current.ToString());
        return tokens;
    }

    private static string StripComments(string text)
    {
        var sb = new StringBuilder(text.Length);
        foreach (var line in text.Split('\n'))
        {
            var cut = line.IndexOf(';');
            sb.Append(cut >= 0 ? line[..cut] : line);
            sb.Append('\n');
        }

        return sb.ToString();
    }

    private static string ExpandParentheses(string text)
    {
        var sb = new StringBuilder(text.Length);
        var depth = 0;
        foreach (var ch in text)
        {
            if (ch == '(')
            {
                depth++;
                sb.Append(' ');
                continue;
            }

            if (ch == ')')
            {
                depth = Math.Max(0, depth - 1);
                sb.Append(' ');
                continue;
            }

            if (ch is '\n' or '\r' && depth > 0)
            {
                sb.Append(' ');
                continue;
            }

            sb.Append(ch);
        }

        return sb.ToString();
    }
}
