using System.Collections.Immutable;
using Dhcpr.Dns.Core.Protocol.Parser;

namespace Dhcpr.Dns.Core.Protocol.RecordData;

public sealed record NextSecure3Data(
    Nsec3HashAlgorithm HashAlgorithm,
    byte Flags,
    ushort Iterations,
    ImmutableArray<byte> Salt,
    ImmutableArray<byte> NextHashedOwnerName,
    ImmutableArray<byte> TypeBitMaps
) : IDomainResourceRecordData
{
    private int? _size;
    public int EstimatedSize => _size ??= 1 + 1 + 2 + 1 + Salt.Length + 1 + NextHashedOwnerName.Length + TypeBitMaps.Length;

    public void WriteTo(ref DnsParsingSpan span)
    {
        var origin = span;
        span = span[2..];
        DomainMessageEncoder.EncodeAndAdvance(ref span, (byte)HashAlgorithm);
        DomainMessageEncoder.EncodeAndAdvance(ref span, Flags);
        DomainMessageEncoder.EncodeAndAdvance(ref span, Iterations);
        
        DomainMessageEncoder.EncodeAndAdvance(ref span, (byte)Salt.Length);
        Salt.CopyTo(span);
        span = span[Salt.Length..];

        DomainMessageEncoder.EncodeAndAdvance(ref span, (byte)NextHashedOwnerName.Length);
        NextHashedOwnerName.CopyTo(span);
        span = span[NextHashedOwnerName.Length..];

        TypeBitMaps.CopyTo(span);
        span = span[TypeBitMaps.Length..];
        DomainMessageEncoder.EncodeAndAdvance(ref origin, (ushort)(span.Offset - (origin.Offset + 2)));
    }

    public static IDomainResourceRecordData ReadFrom(ref ReadOnlyDnsParsingSpan bytes, int dataLength)
    {
        var startOffset = bytes.Offset;
        var hashAlg = (Nsec3HashAlgorithm)DomainMessageEncoder.ReadByteAndAdvance(ref bytes);
        var flags = DomainMessageEncoder.ReadByteAndAdvance(ref bytes);
        var iterations = DomainMessageEncoder.ReadUnsignedShortAndAdvance(ref bytes);
        
        var saltLength = DomainMessageEncoder.ReadByteAndAdvance(ref bytes);
        var salt = bytes.CurrentSpan[..saltLength].ToImmutableArray();
        bytes = bytes[saltLength..];

        var hashLength = DomainMessageEncoder.ReadByteAndAdvance(ref bytes);
        var nextHashedOwnerName = bytes.CurrentSpan[..hashLength].ToImmutableArray();
        bytes = bytes[hashLength..];

        var parsedSoFar = bytes.Offset - startOffset;
        var mapLength = dataLength - parsedSoFar;
        var typeBitMaps = bytes.CurrentSpan[..mapLength].ToImmutableArray();
        bytes = bytes[mapLength..];

        return new NextSecure3Data(hashAlg, flags, iterations, salt, nextHashedOwnerName, typeBitMaps);
    }
}