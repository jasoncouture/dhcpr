using System.Buffers.Binary;

using Dhcpr.Core.Linq;
using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.RecordData;

namespace Dhcpr.Dns.Core.Validation;

/// <summary>Assembles canonical RRsets and verifies RRSIGs via <see cref="IDnssecValidator"/>.</summary>
public static class DnssecRrsetVerifier
{
    public static bool TryVerifyRrset(
        IDnssecValidator validator,
        IReadOnlyList<DomainResourceRecord> rrset,
        IReadOnlyList<DomainResourceRecord> rrsigs,
        IReadOnlyList<DomainResourceRecord> dnsKeys,
        DateTimeOffset now)
    {
        if (rrset.Count == 0 || rrsigs.Count == 0 || dnsKeys.Count == 0)
            return false;

        var nowUnix = (uint)now.ToUnixTimeSeconds();
        foreach (var sigRecord in rrsigs)
        {
            if (sigRecord.Data is not ResourceRecordSignatureData rrsig)
                continue;

            if (nowUnix < rrsig.SignatureInception || nowUnix > rrsig.SignatureExpiration)
                continue;

            if (rrsig.TypeCovered != rrset[0].Type)
                continue;

            foreach (var keyRecord in dnsKeys)
            {
                if (keyRecord.Data is not DomainNameSystemKeyData dnsKey)
                    continue;

                if (!string.Equals(
                        keyRecord.Name.ToString(),
                        rrsig.SignersName.ToString(),
                        StringComparison.OrdinalIgnoreCase))
                    continue;

                var keyTag = validator.CalculateKeyTag(dnsKey, keyRecord);
                if (keyTag != rrsig.KeyTag || dnsKey.Algorithm != rrsig.Algorithm)
                    continue;

                var canonicalRrset = BuildCanonicalRrset(rrset, rrsig.OriginalTtl, rrsig.Labels);
                var rrsigPrefix = EncodeRrsigWithoutSignature(rrsig);
                if (validator.VerifySignature(rrsig, rrsigPrefix, canonicalRrset, dnsKey))
                    return true;
            }
        }

        return false;
    }

    public static byte[] BuildCanonicalRrset(
        IReadOnlyList<DomainResourceRecord> rrset,
        uint originalTtl,
        byte? rrsigLabels = null)
    {
        using var parts = ListPool<byte[]>.Default.Get();
        foreach (var record in rrset.OrderBy(r => r.ToCanonicalWireFormat(originalTtl, rrsigLabels), ByteArrayComparer.Instance))
            parts.Add(record.ToCanonicalWireFormat(originalTtl, rrsigLabels));

        var total = parts.Sum(static p => p.Length);
        var buffer = new byte[total];
        var offset = 0;
        foreach (var part in parts)
        {
            part.CopyTo(buffer, offset);
            offset += part.Length;
        }

        return buffer;
    }

    public static byte[] EncodeRrsigWithoutSignature(ResourceRecordSignatureData rrsig)
    {
        var size = sizeof(ushort) + sizeof(byte) + sizeof(byte) +
                   sizeof(uint) + sizeof(uint) + sizeof(uint) +
                   sizeof(ushort) + rrsig.SignersName.EstimatedSize;
        var buffer = new byte[size];
        var span = buffer.AsSpan();

        BinaryPrimitives.WriteUInt16BigEndian(span, (ushort)rrsig.TypeCovered);
        span = span[2..];
        span[0] = (byte)rrsig.Algorithm;
        span = span[1..];
        span[0] = rrsig.Labels;
        span = span[1..];
        BinaryPrimitives.WriteUInt32BigEndian(span, rrsig.OriginalTtl);
        span = span[4..];
        BinaryPrimitives.WriteUInt32BigEndian(span, rrsig.SignatureExpiration);
        span = span[4..];
        BinaryPrimitives.WriteUInt32BigEndian(span, rrsig.SignatureInception);
        span = span[4..];
        BinaryPrimitives.WriteUInt16BigEndian(span, rrsig.KeyTag);
        span = span[2..];
        DomainResourceRecordCanonicalizationExtensions.EncodeCanonicalName(ref span, rrsig.SignersName);

        return buffer[..(buffer.Length - span.Length)];
    }

    public static IEnumerable<IGrouping<(string Name, DomainRecordType Type), DomainResourceRecord>>
        GroupRrsets(IEnumerable<DomainResourceRecord> records)
        => records
            .Where(static r => r.Type is not DomainRecordType.RRSIG and not DomainRecordType.OPT)
            .GroupBy(
                static r => (Name: r.Name.ToString(), r.Type),
                GroupKeyComparer.Instance);

    private sealed class GroupKeyComparer : IEqualityComparer<(string Name, DomainRecordType Type)>
    {
        public static GroupKeyComparer Instance { get; } = new();

        public bool Equals((string Name, DomainRecordType Type) x, (string Name, DomainRecordType Type) y)
            => x.Type == y.Type &&
               string.Equals(x.Name, y.Name, StringComparison.OrdinalIgnoreCase);

        public int GetHashCode((string Name, DomainRecordType Type) obj)
            => HashCode.Combine(StringComparer.OrdinalIgnoreCase.GetHashCode(obj.Name), obj.Type);
    }

    public static IReadOnlyList<DomainResourceRecord> FindCoveringRrsigs(
        IEnumerable<DomainResourceRecord> records,
        DomainLabels owner,
        DomainRecordType typeCovered)
        => records
            .Where(r =>
                r.Type is DomainRecordType.RRSIG &&
                r.Data is ResourceRecordSignatureData sig &&
                sig.TypeCovered == typeCovered &&
                string.Equals(r.Name.ToString(), owner.ToString(), StringComparison.OrdinalIgnoreCase))
            .ToList();

    private sealed class ByteArrayComparer : IComparer<byte[]>
    {
        public static ByteArrayComparer Instance { get; } = new();

        public int Compare(byte[]? x, byte[]? y)
        {
            if (ReferenceEquals(x, y)) return 0;
            if (x is null) return -1;
            if (y is null) return 1;
            var len = Math.Min(x.Length, y.Length);
            for (var i = 0; i < len; i++)
            {
                var c = x[i].CompareTo(y[i]);
                if (c != 0) return c;
            }

            return x.Length.CompareTo(y.Length);
        }
    }
}
