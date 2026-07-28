using System.Collections.Immutable;

using Dhcpr.Dns.Core.Protocol.Parser;

namespace Dhcpr.Dns.Core.Protocol.RecordData;

public sealed record SshFingerprintData(
    byte Algorithm,
    byte FingerprintType,
    ImmutableArray<byte> Fingerprint) : IDomainResourceRecordData
{
    public int EstimatedSize => 2 + Fingerprint.Length;

    public void WriteTo(ref DnsParsingSpan span)
    {
        var origin = span;
        span = span[2..];
        DomainMessageEncoder.EncodeAndAdvance(ref span, Algorithm);
        DomainMessageEncoder.EncodeAndAdvance(ref span, FingerprintType);
        Fingerprint.CopyTo(span);
        span = span[Fingerprint.Length..];
        DomainMessageEncoder.EncodeAndAdvance(ref origin, (ushort)(span.Offset - (origin.Offset + 2)));
    }

    public static IDomainResourceRecordData ReadFrom(ref ReadOnlyDnsParsingSpan bytes, int dataLength)
    {
        var algorithm = DomainMessageEncoder.ReadByteAndAdvance(ref bytes);
        var fpType = DomainMessageEncoder.ReadByteAndAdvance(ref bytes);
        var fingerprint = bytes.CurrentSpan[..(dataLength - 2)].ToImmutableArray();
        bytes = bytes[(dataLength - 2)..];
        return new SshFingerprintData(algorithm, fpType, fingerprint);
    }
}
