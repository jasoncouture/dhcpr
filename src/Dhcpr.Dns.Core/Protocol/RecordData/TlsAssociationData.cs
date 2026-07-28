using System.Collections.Immutable;

using Dhcpr.Dns.Core.Protocol.Parser;

namespace Dhcpr.Dns.Core.Protocol.RecordData;

public sealed record TlsAssociationData(
    byte CertificateUsage,
    byte Selector,
    byte MatchingType,
    ImmutableArray<byte> CertificateAssociationData) : IDomainResourceRecordData
{
    public int EstimatedSize => 3 + CertificateAssociationData.Length;

    public void WriteTo(ref DnsParsingSpan span)
    {
        var origin = span;
        span = span[2..];
        DomainMessageEncoder.EncodeAndAdvance(ref span, CertificateUsage);
        DomainMessageEncoder.EncodeAndAdvance(ref span, Selector);
        DomainMessageEncoder.EncodeAndAdvance(ref span, MatchingType);
        CertificateAssociationData.CopyTo(span);
        span = span[CertificateAssociationData.Length..];
        DomainMessageEncoder.EncodeAndAdvance(ref origin, (ushort)(span.Offset - (origin.Offset + 2)));
    }

    public static IDomainResourceRecordData ReadFrom(ref ReadOnlyDnsParsingSpan bytes, int dataLength)
    {
        var usage = DomainMessageEncoder.ReadByteAndAdvance(ref bytes);
        var selector = DomainMessageEncoder.ReadByteAndAdvance(ref bytes);
        var matching = DomainMessageEncoder.ReadByteAndAdvance(ref bytes);
        var assoc = bytes.CurrentSpan[..(dataLength - 3)].ToImmutableArray();
        bytes = bytes[(dataLength - 3)..];
        return new TlsAssociationData(usage, selector, matching, assoc);
    }
}
