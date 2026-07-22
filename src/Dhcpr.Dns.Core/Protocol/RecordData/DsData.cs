using System.Collections.Immutable;
using Dhcpr.Dns.Core.Protocol.Parser;

namespace Dhcpr.Dns.Core.Protocol.RecordData;

public sealed record DsData(
    ushort KeyTag,
    byte Algorithm,
    byte DigestType,
    ImmutableArray<byte> Digest
) : IDomainResourceRecordData
{
    public int EstimatedSize => sizeof(ushort) + sizeof(byte) + sizeof(byte) + Digest.Length;

    public void WriteTo(ref DnsParsingSpan span)
    {
        var origin = span;
        span = span[2..];
        DomainMessageEncoder.EncodeAndAdvance(ref span, KeyTag);
        DomainMessageEncoder.EncodeAndAdvance(ref span, Algorithm);
        DomainMessageEncoder.EncodeAndAdvance(ref span, DigestType);
        Digest.CopyTo(span);
        span = span[Digest.Length..];
        DomainMessageEncoder.EncodeAndAdvance(ref origin, (ushort)(span.Offset - (origin.Offset + 2)));
    }

    public static IDomainResourceRecordData ReadFrom(ref ReadOnlyDnsParsingSpan bytes, int dataLength)
    {
        var keyTag = DomainMessageEncoder.ReadUnsignedShortAndAdvance(ref bytes);
        var algorithm = DomainMessageEncoder.ReadByteAndAdvance(ref bytes);
        var digestType = DomainMessageEncoder.ReadByteAndAdvance(ref bytes);
        var digestLength = dataLength - 4;
        var digestData = bytes.CurrentSpan[..digestLength].ToImmutableArray();
        bytes = bytes[digestLength..];
        
        return new DsData(keyTag, algorithm, digestType, digestData);
    }
}
