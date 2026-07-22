using System.Collections.Immutable;
using Dhcpr.Dns.Core.Protocol.Parser;

namespace Dhcpr.Dns.Core.Protocol.RecordData;

public sealed record Nsec3ParamData(
    byte HashAlgorithm,
    byte Flags,
    ushort Iterations,
    ImmutableArray<byte> Salt
) : IDomainResourceRecordData
{
    private int? _size;
    public int EstimatedSize => _size ??= 1 + 1 + 2 + 1 + Salt.Length;

    public void WriteTo(ref DnsParsingSpan span)
    {
        var origin = span;
        span = span[2..];
        DomainMessageEncoder.EncodeAndAdvance(ref span, HashAlgorithm);
        DomainMessageEncoder.EncodeAndAdvance(ref span, Flags);
        DomainMessageEncoder.EncodeAndAdvance(ref span, Iterations);
        
        DomainMessageEncoder.EncodeAndAdvance(ref span, (byte)Salt.Length);
        Salt.CopyTo(span);
        span = span[Salt.Length..];
        DomainMessageEncoder.EncodeAndAdvance(ref origin, (ushort)(span.Offset - (origin.Offset + 2)));
    }

    public static IDomainResourceRecordData ReadFrom(ref ReadOnlyDnsParsingSpan bytes, int dataLength)
    {
        var hashAlg = DomainMessageEncoder.ReadByteAndAdvance(ref bytes);
        var flags = DomainMessageEncoder.ReadByteAndAdvance(ref bytes);
        var iterations = DomainMessageEncoder.ReadUnsignedShortAndAdvance(ref bytes);
        
        var saltLength = DomainMessageEncoder.ReadByteAndAdvance(ref bytes);
        var salt = bytes.CurrentSpan[..saltLength].ToImmutableArray();
        bytes = bytes[saltLength..];

        return new Nsec3ParamData(hashAlg, flags, iterations, salt);
    }
}