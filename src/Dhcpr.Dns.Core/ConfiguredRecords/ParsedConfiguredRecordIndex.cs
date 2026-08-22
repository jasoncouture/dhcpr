using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Sockets;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.RecordData;
using Dhcpr.Dns.Core.Protocol.Zone;

namespace Dhcpr.Dns.Core.ConfiguredRecords;

public sealed class ParsedConfiguredRecordIndex
{
    public const int DefaultTtlSeconds = 300;

    private static readonly ImmutableDictionary<string, ImmutableArray<ParsedConfiguredRecord>> EmptyMap =
        ImmutableDictionary<string, ImmutableArray<ParsedConfiguredRecord>>.Empty
            .WithComparers(StringComparer.OrdinalIgnoreCase);

    public static ParsedConfiguredRecordIndex Empty { get; } = new(EmptyMap, EmptyMap);

    private readonly ImmutableDictionary<string, ImmutableArray<ParsedConfiguredRecord>> _byOwner;
    private readonly ImmutableDictionary<string, ImmutableArray<ParsedConfiguredRecord>> _wildcardsByParent;

    private ParsedConfiguredRecordIndex(
        ImmutableDictionary<string, ImmutableArray<ParsedConfiguredRecord>> byOwner,
        ImmutableDictionary<string, ImmutableArray<ParsedConfiguredRecord>> wildcardsByParent)
    {
        _byOwner = byOwner;
        _wildcardsByParent = wildcardsByParent;
    }

    public bool IsEmpty => _byOwner.IsEmpty && _wildcardsByParent.IsEmpty;

    public static bool TryBuild(
        IReadOnlyList<DnsRecordConfiguration>? records,
        [NotNullWhen(true)] out ParsedConfiguredRecordIndex? index,
        [NotNullWhen(false)] out string? error)
    {
        index = Empty;
        error = null;
        if (records is null || records.Count == 0)
            return true;

        var byOwner = new Dictionary<string, List<ParsedConfiguredRecord>>(StringComparer.OrdinalIgnoreCase);
        var wildcards = new Dictionary<string, List<ParsedConfiguredRecord>>(StringComparer.OrdinalIgnoreCase);
        var parsed = new List<ParsedConfiguredRecord>(records.Count);

        for (var i = 0; i < records.Count; i++)
        {
            if (!TryParseRecord(records[i] ?? new DnsRecordConfiguration(), i, out var record, out error))
            {
                index = null;
                return false;
            }

            parsed.Add(record);
            Add(byOwner, record.Owner, record);
            if (record.IsWildcard)
                Add(wildcards, record.WildcardParent, record);
        }

        if (!TryValidateCnameExclusivity(parsed, out error))
        {
            index = null;
            return false;
        }

        index = new ParsedConfiguredRecordIndex(Freeze(byOwner), Freeze(wildcards));
        return true;
    }

    public DomainMessage? TryAnswer(DomainMessage request, IPAddress? client)
    {
        if (IsEmpty || request.Questions.Length == 0)
            return null;

        var question = request.Questions[0];
        if (question.Class is not DomainRecordClass.IN)
            return null;

        var qname = RootZoneSnapshot.NormalizeOwner(question.Name.ToString());
        if (_byOwner.TryGetValue(qname, out var exact))
        {
            var visible = VisibleAny(exact, client);
            if (visible.Length > 0)
                return AnswerOwner(request, question, visible, synthesizeName: null, client);
        }

        foreach (var ancestor in Ancestors(qname))
        {
            if (!_wildcardsByParent.TryGetValue(ancestor, out var wildcards))
            {
                if (Exists(ancestor, client))
                    break;
                continue;
            }

            var visibleWildcards = VisibleAny(wildcards, client);
            if (visibleWildcards.Length == 0)
            {
                if (Exists(ancestor, client))
                    break;
                continue;
            }

            return AnswerOwner(request, question, visibleWildcards, question.Name, client);
        }

        return TryReferral(request, qname, client);
    }

    private DomainMessage? AnswerOwner(
        DomainMessage request,
        DomainQuestion question,
        ImmutableArray<ParsedConfiguredRecord> visible,
        DomainLabels? synthesizeName,
        IPAddress? client)
    {
        var ofType = PreferRestricted(visible, question.Type);
        if (ofType.Length > 0)
        {
            var answers = ToRecords(ofType, synthesizeName);
            var additional = question.Type is DomainRecordType.NS
                ? CollectGlue(ofType, client)
                : ImmutableArray<DomainResourceRecord>.Empty;
            return Respond(request, answers, authorities: null, additional, DomainResponseCode.NoError, authoritative: true);
        }

        if (question.Type is not DomainRecordType.CNAME)
        {
            var cnames = PreferRestricted(visible, DomainRecordType.CNAME);
            if (cnames.Length > 0)
                return Respond(request, ToRecords(cnames, synthesizeName), null, null, DomainResponseCode.NoError, true);
        }

        return Respond(request, answers: null, authorities: null, additional: null, DomainResponseCode.NoError, true);
    }

    private DomainMessage? TryReferral(DomainMessage request, string qname, IPAddress? client)
    {
        foreach (var ancestor in Ancestors(qname))
        {
            if (!_byOwner.TryGetValue(ancestor, out var records))
                continue;

            var ns = PreferRestricted(VisibleAny(records, client), DomainRecordType.NS);
            if (ns.Length == 0)
                continue;

            return Respond(
                request,
                answers: null,
                authorities: ToRecords(ns, synthesizeName: null),
                additional: CollectGlue(ns, client),
                DomainResponseCode.NoError,
                authoritative: false);
        }

        return null;
    }

    private bool Exists(string owner, IPAddress? client)
    {
        if (_byOwner.TryGetValue(owner, out var exact) && VisibleAny(exact, client).Length > 0)
            return true;
        return _wildcardsByParent.TryGetValue(owner, out var wild) && VisibleAny(wild, client).Length > 0;
    }

    private ImmutableArray<DomainResourceRecord> CollectGlue(
        ImmutableArray<ParsedConfiguredRecord> nsRecords,
        IPAddress? client)
    {
        var glue = ImmutableArray.CreateBuilder<DomainResourceRecord>();
        foreach (var ns in nsRecords)
        {
            if (ns.Data is not NameData nameData)
                continue;

            var host = RootZoneSnapshot.NormalizeOwner(nameData.Name.ToString());
            if (!_byOwner.TryGetValue(host, out var hostRecords))
                continue;

            var visible = VisibleAny(hostRecords, client);
            foreach (var record in PreferRestricted(visible, DomainRecordType.A))
                glue.Add(ToRecord(record, synthesizeName: null));
            foreach (var record in PreferRestricted(visible, DomainRecordType.AAAA))
                glue.Add(ToRecord(record, synthesizeName: null));
        }

        return glue.ToImmutable();
    }

    private static ImmutableArray<ParsedConfiguredRecord> VisibleAny(
        ImmutableArray<ParsedConfiguredRecord> records,
        IPAddress? client)
        => records.Where(r => r.Clients.AllowsClient(client)).ToImmutableArray();

    private static ImmutableArray<ParsedConfiguredRecord> PreferRestricted(
        ImmutableArray<ParsedConfiguredRecord> visible,
        DomainRecordType type)
    {
        var ofType = visible.Where(r => r.Type == type).ToImmutableArray();
        if (ofType.Length == 0)
            return ofType;

        var restricted = ofType.Where(static r => r.Clients.IsRestricted).ToImmutableArray();
        return restricted.Length > 0 ? restricted : ofType;
    }

    private static ImmutableArray<DomainResourceRecord> ToRecords(
        ImmutableArray<ParsedConfiguredRecord> records,
        DomainLabels? synthesizeName)
        => records.Select(r => ToRecord(r, synthesizeName)).ToImmutableArray();

    private static DomainResourceRecord ToRecord(ParsedConfiguredRecord record, DomainLabels? synthesizeName)
        => new(
            synthesizeName ?? record.Name,
            record.Type,
            DomainRecordClass.IN,
            record.TimeToLive,
            record.Data);

    private static DomainMessage Respond(
        DomainMessage request,
        IEnumerable<DomainResourceRecord>? answers,
        IEnumerable<DomainResourceRecord>? authorities,
        IEnumerable<DomainResourceRecord>? additional,
        DomainResponseCode code,
        bool authoritative)
    {
        var response = DomainMessage.CreateResponse(request, answers, authorities, additional, code);
        return response with
        {
            Flags = response.Flags with
            {
                Authoritative = authoritative,
                RecursionAvailable = true
            }
        };
    }

    private static IEnumerable<string> Ancestors(string qname)
    {
        if (qname.Length == 0)
            yield break;

        var labels = qname.Split('.');
        for (var i = 1; i < labels.Length; i++)
            yield return string.Join('.', labels.AsSpan(i).ToArray());

        yield return string.Empty;
    }

    private static void Add(
        Dictionary<string, List<ParsedConfiguredRecord>> map,
        string key,
        ParsedConfiguredRecord record)
    {
        if (!map.TryGetValue(key, out var list))
        {
            list = [];
            map[key] = list;
        }

        list.Add(record);
    }

    private static ImmutableDictionary<string, ImmutableArray<ParsedConfiguredRecord>> Freeze(
        Dictionary<string, List<ParsedConfiguredRecord>> map)
    {
        var builder = ImmutableDictionary.CreateBuilder<string, ImmutableArray<ParsedConfiguredRecord>>(
            StringComparer.OrdinalIgnoreCase);
        foreach (var (key, list) in map)
            builder[key] = list.ToImmutableArray();
        return builder.ToImmutable();
    }

    private static bool TryValidateCnameExclusivity(
        List<ParsedConfiguredRecord> parsed,
        [NotNullWhen(false)] out string? error)
    {
        var groups = parsed.GroupBy(static r => (r.Owner, r.Clients.CanonicalKey()), StringTupleComparer.Instance);
        foreach (var group in groups)
        {
            var hasCname = false;
            var hasOther = false;
            foreach (var record in group)
            {
                if (record.Type is DomainRecordType.CNAME)
                    hasCname = true;
                else
                    hasOther = true;

                if (!hasCname || !hasOther)
                    continue;

                error =
                    $"DNS:Records: CNAME at \"{group.Key.Owner}\" cannot share the same Clients set with another type";
                return false;
            }
        }

        error = null;
        return true;
    }

    private static bool TryParseRecord(
        DnsRecordConfiguration config,
        int index,
        [NotNullWhen(true)] out ParsedConfiguredRecord? record,
        [NotNullWhen(false)] out string? error)
    {
        record = null;
        var name = config.Name?.Trim().TrimEnd('.');
        if (string.IsNullOrWhiteSpace(name))
        {
            error = $"DNS:Records[{index}].Name is empty";
            return false;
        }

        DomainLabels labels;
        try
        {
            labels = new DomainLabels(name);
        }
        catch (InvalidOperationException)
        {
            error = $"DNS:Records[{index}].Name is not a valid domain name: {name}";
            return false;
        }

        if (labels.Count == 0)
        {
            error = $"DNS:Records[{index}].Name is empty";
            return false;
        }

        for (var i = 1; i < labels.Count; i++)
        {
            if (!string.Equals(labels[i], "*", StringComparison.Ordinal))
                continue;

            error = $"DNS:Records[{index}].Name may only use '*' as the leftmost label";
            return false;
        }

        var owner = RootZoneSnapshot.NormalizeOwner(name);
        var isWildcard = string.Equals(labels[0], "*", StringComparison.Ordinal);
        var wildcardParent = !isWildcard
            ? string.Empty
            : labels.Count == 1
                ? string.Empty
                : RootZoneSnapshot.NormalizeOwner(string.Join('.', labels.Skip(1)));

        if (!TryParseType(config.Type, out var type, out error))
        {
            error = $"DNS:Records[{index}].Type {error}";
            return false;
        }

        if (config.Ttl is <= 0)
        {
            error = $"DNS:Records[{index}].Ttl must be greater than 0";
            return false;
        }

        var ttl = TimeSpan.FromSeconds(config.Ttl ?? DefaultTtlSeconds);
        if (!TryParseValue(type, config.Value, out var data, out error))
        {
            error = $"DNS:Records[{index}].Value {error}";
            return false;
        }

        config.Clients ??= [];
        if (!ClientAccessList.TryParse(config.Clients, out var clients, out error))
        {
            error = $"DNS:Records[{index}].Clients{error}";
            return false;
        }

        record = new ParsedConfiguredRecord(
            owner,
            labels,
            type,
            ttl,
            data,
            clients,
            isWildcard,
            wildcardParent);
        error = null;
        return true;
    }

    private static bool TryParseType(
        string? type,
        out DomainRecordType parsed,
        [NotNullWhen(false)] out string? error)
    {
        parsed = default;
        if (string.IsNullOrWhiteSpace(type))
        {
            error = "is empty";
            return false;
        }

        if (!Enum.TryParse(type.Trim(), ignoreCase: true, out parsed) ||
            parsed is not (DomainRecordType.A or DomainRecordType.AAAA or DomainRecordType.CNAME
                or DomainRecordType.NS))
        {
            error = $"must be A, AAAA, CNAME, or NS: {type}";
            parsed = default;
            return false;
        }

        error = null;
        return true;
    }

    private static bool TryParseValue(
        DomainRecordType type,
        string? value,
        [NotNullWhen(true)] out IDomainResourceRecordData? data,
        [NotNullWhen(false)] out string? error)
    {
        data = null;
        var raw = value?.Trim().TrimEnd('.');
        if (string.IsNullOrWhiteSpace(raw))
        {
            error = "is empty";
            return false;
        }

        switch (type)
        {
            case DomainRecordType.A:
                if (!IPAddress.TryParse(raw, out var v4) || v4.AddressFamily is not AddressFamily.InterNetwork)
                {
                    error = $"is not an IPv4 address: {raw}";
                    return false;
                }

                data = new IPAddressData(v4);
                error = null;
                return true;
            case DomainRecordType.AAAA:
                if (!IPAddress.TryParse(raw, out var v6) || v6.AddressFamily is not AddressFamily.InterNetworkV6)
                {
                    error = $"is not an IPv6 address: {raw}";
                    return false;
                }

                data = new IPAddressData(v6);
                error = null;
                return true;
            case DomainRecordType.CNAME:
            case DomainRecordType.NS:
                DomainLabels target;
                try
                {
                    target = new DomainLabels(raw);
                }
                catch (InvalidOperationException)
                {
                    error = $"is not a valid domain name: {raw}";
                    return false;
                }

                if (target.Count == 0 || target.Any(static label => label == "*"))
                {
                    error = $"is not a valid domain name: {raw}";
                    return false;
                }

                data = new NameData(target);
                error = null;
                return true;
            default:
                error = "is not supported";
                return false;
        }
    }

    private sealed class StringTupleComparer : IEqualityComparer<(string Owner, string Clients)>
    {
        public static StringTupleComparer Instance { get; } = new();

        public bool Equals((string Owner, string Clients) x, (string Owner, string Clients) y)
            => StringComparer.OrdinalIgnoreCase.Equals(x.Owner, y.Owner)
               && StringComparer.Ordinal.Equals(x.Clients, y.Clients);

        public int GetHashCode((string Owner, string Clients) obj)
            => HashCode.Combine(
                StringComparer.OrdinalIgnoreCase.GetHashCode(obj.Owner),
                StringComparer.Ordinal.GetHashCode(obj.Clients));
    }
}
