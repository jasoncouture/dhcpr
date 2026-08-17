using System.Collections.Immutable;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.RecordData;

namespace Dhcpr.Dns.Core.Validation;

/// <summary>
/// RFC 5155 NSEC3 closest-encloser / NODATA / Opt-Out proof helpers.
/// </summary>
public static class DnssecNsec3Proof
{
    public const byte OptOutFlag = 0x01;

    public readonly record struct Nsec3Rr(DomainResourceRecord Record, NextSecure3Data Data, byte[] OwnerHash);

    public static bool TryParseOwnerHash(DomainLabels owner, Span<byte> hashBuffer, out int hashLength)
    {
        hashLength = 0;
        if (owner.Labels.Length == 0)
            return false;

        var label = owner.Labels[0].Label;
        return DnssecBase32Hex.TryDecode(label.AsSpan(), hashBuffer, out hashLength) && hashLength > 0;
    }

    public static List<Nsec3Rr> Collect(IEnumerable<DomainResourceRecord> records)
    {
        var list = new List<Nsec3Rr>();
        Span<byte> hashBuf = stackalloc byte[64];
        foreach (var record in records)
        {
            if (record.Type is not DomainRecordType.NSEC3 || record.Data is not NextSecure3Data data)
                continue;
            if (!TryParseOwnerHash(record.Name, hashBuf, out var len))
                continue;
            list.Add(new Nsec3Rr(record, data, hashBuf[..len].ToArray()));
        }

        return list;
    }

    public static Nsec3Rr? FindExact(IReadOnlyList<Nsec3Rr> nsec3s, ReadOnlySpan<byte> hash)
    {
        foreach (var item in nsec3s)
        {
            if (item.OwnerHash.AsSpan().SequenceEqual(hash))
                return item;
        }

        return null;
    }

    public static Nsec3Rr? FindCover(
        IDnssecValidator crypto,
        IReadOnlyList<Nsec3Rr> nsec3s,
        ReadOnlySpan<byte> hash)
    {
        foreach (var item in nsec3s)
        {
            if (crypto.CoversHash(item.Data, item.OwnerHash, hash))
                return item;
        }

        return null;
    }

    public static DomainLabels? ParentName(DomainLabels name)
    {
        if (name.Labels.Length == 0)
            return null;
        if (name.Labels.Length == 1)
            return DomainLabels.Empty;
        return new DomainLabels(name.Labels[1..]);
    }

    public static DomainLabels? NextCloser(DomainLabels qname, DomainLabels closestEncloser)
    {
        var closerLabelCount = closestEncloser.Labels.Length + 1;
        if (closerLabelCount > qname.Labels.Length)
            return null;
        var start = qname.Labels.Length - closerLabelCount;
        return new DomainLabels(qname.Labels[start..]);
    }

    public static DomainLabels WildcardAt(DomainLabels closestEncloser)
    {
        if (closestEncloser.Labels.Length == 0)
            return new DomainLabels(ImmutableArray.Create(new DomainLabel("*")));

        var labels = ImmutableArray.CreateBuilder<DomainLabel>();
        labels.Add(new DomainLabel("*"));
        labels.AddRange(closestEncloser.Labels);
        return new DomainLabels(labels.ToImmutable());
    }

    /// <summary>
    /// Walks qname → parents until an NSEC3 owner hash matches.
    /// </summary>
    public static bool TryFindClosestEncloser(
        IDnssecValidator crypto,
        IReadOnlyList<Nsec3Rr> nsec3s,
        DomainLabels qname,
        NextSecure3Data parameters,
        out DomainLabels closestEncloser,
        out Nsec3Rr closestRecord)
    {
        closestEncloser = DomainLabels.Empty;
        closestRecord = default;

        var candidate = qname;
        while (true)
        {
            var hash = crypto.CalculateNsec3Hash(candidate, parameters);
            if (hash.Length == 0)
                return false;

            var match = FindExact(nsec3s, hash);
            if (match is { } found)
            {
                closestEncloser = candidate;
                closestRecord = found;
                return true;
            }

            var parent = ParentName(candidate);
            if (parent is null)
                return false;
            candidate = parent;
        }
    }
}
