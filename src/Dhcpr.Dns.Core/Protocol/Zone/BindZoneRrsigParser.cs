using System.Collections.Immutable;
using System.Globalization;

using Dhcpr.Dns.Core.Protocol.RecordData;

namespace Dhcpr.Dns.Core.Protocol.Zone;

/// <summary>
/// RFC 4034 §3.2 RRSIG presentation format. DnsZone cannot parse these lines;
/// this walk extracts them after parenthesis expansion.
/// </summary>
public static class BindZoneRrsigParser
{
    public static IReadOnlyList<DomainResourceRecord> Parse(string text, string? origin = null)
    {
        var currentOrigin = string.IsNullOrWhiteSpace(origin) ? "." : origin.Trim();
        var defaultTtl = (uint?)null;
        var lastTtl = (uint?)null;
        var lastOwner = Qualify("@", currentOrigin);
        var records = new List<DomainResourceRecord>();

        var expanded = BindZoneUnsupportedFilter.ExpandParentheses(text);
        foreach (var rawLine in expanded.Split('\n'))
        {
            var line = BindZoneUnsupportedFilter.StripComment(rawLine.TrimEnd('\r')).Trim();
            if (line.Length == 0)
                continue;

            if (line[0] == '$')
            {
                ApplyDirective(line, ref currentOrigin, ref defaultTtl);
                continue;
            }

            if (!TryReadHeader(
                    rawLine.TrimEnd('\r'),
                    line,
                    lastOwner,
                    currentOrigin,
                    defaultTtl,
                    lastTtl,
                    out var owner,
                    out var ttl,
                    out var type,
                    out var tokens,
                    out var rdataStart))
                continue;

            lastOwner = owner;
            lastTtl = ttl;

            if (!type.Equals("RRSIG", StringComparison.OrdinalIgnoreCase))
                continue;

            if (TryMapRrsig(owner, ttl, tokens, rdataStart, currentOrigin) is { } record)
                records.Add(record);
        }

        return records;
    }

    private static void ApplyDirective(string line, ref string origin, ref uint? defaultTtl)
    {
        var tokens = BindZoneUnsupportedFilter.Tokenize(line);
        if (tokens.Count < 2)
            return;

        if (tokens[0].Equals("$ORIGIN", StringComparison.OrdinalIgnoreCase))
            origin = tokens[1];
        else if (tokens[0].Equals("$TTL", StringComparison.OrdinalIgnoreCase) &&
                 BindZoneUnsupportedFilter.TryParseTtl(tokens[1], out var ttl))
            defaultTtl = ttl;
    }

    private static bool TryReadHeader(
        string rawLine,
        string line,
        DomainLabels lastOwner,
        string origin,
        uint? defaultTtl,
        uint? lastTtl,
        out DomainLabels owner,
        out uint ttl,
        out string type,
        out List<string> tokens,
        out int rdataStart)
    {
        owner = lastOwner;
        ttl = defaultTtl ?? lastTtl ?? 3600;
        type = "";
        tokens = BindZoneUnsupportedFilter.Tokenize(line);
        rdataStart = 0;
        if (tokens.Count == 0)
            return false;

        var blankOwner = rawLine.Length > 0 && char.IsWhiteSpace(rawLine[0]);
        var index = 0;
        if (!blankOwner && LooksLikeOwner(tokens[0]))
        {
            owner = Qualify(tokens[0], origin);
            index++;
        }

        uint? parsedTtl = null;
        while (index < tokens.Count)
        {
            if (BindZoneUnsupportedFilter.IsClass(tokens[index]))
            {
                index++;
                continue;
            }

            if (BindZoneUnsupportedFilter.TryParseTtl(tokens[index], out var value))
            {
                parsedTtl = value;
                index++;
                continue;
            }

            break;
        }

        if (index >= tokens.Count)
            return false;

        type = tokens[index];
        rdataStart = index + 1;
        if (parsedTtl is { } explicitTtl)
            ttl = explicitTtl;
        return true;
    }

    private static DomainResourceRecord? TryMapRrsig(
        DomainLabels owner,
        uint ttl,
        List<string> tokens,
        int rdataStart,
        string origin)
    {
        // type-covered algorithm labels orig-ttl expiration inception key-tag signer signature…
        if (tokens.Count - rdataStart < 9)
            return null;

        if (!TryParseTypeCovered(tokens[rdataStart], out var typeCovered))
            return null;
        if (!byte.TryParse(tokens[rdataStart + 1], NumberStyles.Integer, CultureInfo.InvariantCulture, out var algorithm))
            return null;
        if (!byte.TryParse(tokens[rdataStart + 2], NumberStyles.Integer, CultureInfo.InvariantCulture, out var labels))
            return null;
        if (!BindZoneUnsupportedFilter.TryParseTtl(tokens[rdataStart + 3], out var originalTtl))
            return null;
        if (!TryParseTimestamp(tokens[rdataStart + 4], out var expiration))
            return null;
        if (!TryParseTimestamp(tokens[rdataStart + 5], out var inception))
            return null;
        if (!ushort.TryParse(tokens[rdataStart + 6], NumberStyles.Integer, CultureInfo.InvariantCulture, out var keyTag))
            return null;

        var signer = Qualify(tokens[rdataStart + 7], origin);
        var signatureText = string.Concat(tokens.Skip(rdataStart + 8));
        if (!TryDecodeBase64(signatureText, out var signature))
            return null;

        return new DomainResourceRecord(
            owner,
            DomainRecordType.RRSIG,
            DomainRecordClass.IN,
            TimeSpan.FromSeconds(ttl),
            new ResourceRecordSignatureData(
                typeCovered,
                (DnssecAlgorithmType)algorithm,
                labels,
                originalTtl,
                expiration,
                inception,
                keyTag,
                signer,
                signature.ToImmutableArray()));
    }

    private static bool TryParseTypeCovered(string token, out DomainRecordType type)
    {
        if (Enum.TryParse(token, ignoreCase: true, out type) &&
            Enum.IsDefined(type))
            return true;

        if (token.StartsWith("TYPE", StringComparison.OrdinalIgnoreCase) &&
            ushort.TryParse(token.AsSpan(4), NumberStyles.Integer, CultureInfo.InvariantCulture, out var numeric))
        {
            type = (DomainRecordType)numeric;
            return true;
        }

        type = default;
        return false;
    }

    private static bool TryDecodeBase64(string text, out byte[] bytes)
    {
        var pad = (4 - text.Length % 4) % 4;
        if (pad > 0)
            text += new string('=', pad);

        try
        {
            bytes = Convert.FromBase64String(text);
            return true;
        }
        catch (FormatException)
        {
            bytes = [];
            return false;
        }
    }

    private static bool TryParseTimestamp(string token, out uint unixSeconds)
    {
        unixSeconds = 0;
        if (!DateTime.TryParseExact(
                token,
                "yyyyMMddHHmmss",
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out var utc))
            return false;

        var seconds = new DateTimeOffset(utc, TimeSpan.Zero).ToUnixTimeSeconds();
        if (seconds is < 0 or > uint.MaxValue)
            return false;

        unixSeconds = (uint)seconds;
        return true;
    }

    private static bool LooksLikeOwner(string token)
        => !BindZoneUnsupportedFilter.IsClass(token) &&
           !BindZoneUnsupportedFilter.IsTtl(token) &&
           !LooksLikeType(token);

    private static bool LooksLikeType(string token)
    {
        if (BindZoneUnsupportedFilter.IsSupportedType(token))
            return true;

        if (token.Equals("RRSIG", StringComparison.OrdinalIgnoreCase) ||
            token.Equals("DNSKEY", StringComparison.OrdinalIgnoreCase) ||
            token.Equals("NSEC", StringComparison.OrdinalIgnoreCase) ||
            token.Equals("NSEC3", StringComparison.OrdinalIgnoreCase) ||
            token.Equals("NSEC3PARAM", StringComparison.OrdinalIgnoreCase) ||
            token.Equals("ZONEMD", StringComparison.OrdinalIgnoreCase))
            return true;

        return token.StartsWith("TYPE", StringComparison.OrdinalIgnoreCase) &&
               token.Length > 4 &&
               ushort.TryParse(token.AsSpan(4), NumberStyles.Integer, CultureInfo.InvariantCulture, out _);
    }

    private static DomainLabels Qualify(string name, string origin)
    {
        if (name.Equals("@", StringComparison.Ordinal))
            return ToLabels(origin);
        if (name.Equals(".", StringComparison.Ordinal))
            return DomainLabels.Empty;
        if (name.EndsWith('.'))
            return ToLabels(name);

        var originTrim = origin.Trim().TrimEnd('.');
        return originTrim.Length == 0
            ? ToLabels(name)
            : ToLabels($"{name}.{originTrim}");
    }

    private static DomainLabels ToLabels(string name)
    {
        name = name.Trim().TrimEnd('.');
        return string.IsNullOrEmpty(name) ? DomainLabels.Empty : new DomainLabels(name);
    }
}
