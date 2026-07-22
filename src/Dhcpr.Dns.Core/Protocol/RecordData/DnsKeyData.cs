using System.Collections.Immutable;
using Dhcpr.Dns.Core.Protocol.Parser;

namespace Dhcpr.Dns.Core.Protocol.RecordData;

public sealed record DnsKeyData(
    ushort Flags,
    byte Protocol,
    byte Algorithm,
    ImmutableArray<byte> PublicKey
) : IDomainResourceRecordData
{
    public int EstimatedSize => sizeof(ushort) + sizeof(byte) + sizeof(byte) + PublicKey.Length;

    public void WriteTo(ref DnsParsingSpan span)
    {
        var origin = span;
        span = span[2..];
        DomainMessageEncoder.EncodeAndAdvance(ref span, Flags);
        DomainMessageEncoder.EncodeAndAdvance(ref span, Protocol);
        DomainMessageEncoder.EncodeAndAdvance(ref span, Algorithm);
        PublicKey.CopyTo(span);
        span = span[PublicKey.Length..];
        DomainMessageEncoder.EncodeAndAdvance(ref origin, (ushort)(span.Offset - (origin.Offset + 2)));
    }

    public static IDomainResourceRecordData ReadFrom(ref ReadOnlyDnsParsingSpan bytes, int dataLength)
    {
        var flags = DomainMessageEncoder.ReadUnsignedShortAndAdvance(ref bytes);
        var protocol = DomainMessageEncoder.ReadByteAndAdvance(ref bytes);
        var algorithm = DomainMessageEncoder.ReadByteAndAdvance(ref bytes);
        var keyLength = dataLength - 4;
        var keyData = bytes.CurrentSpan[..keyLength].ToImmutableArray();
        bytes = bytes[keyLength..];
        
        return new DnsKeyData(flags, protocol, algorithm, keyData);
    }
}
