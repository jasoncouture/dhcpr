using System.Collections.Immutable;
using Dhcpr.Core;
using Dhcpr.Dns.Core.Protocol.Parser;

namespace Dhcpr.Dns.Core.Protocol.RecordData;

public sealed record ResourceRecordSignatureData(
    DomainRecordType TypeCovered,
    DnssecAlgorithmType Algorithm,
    byte Labels,
    uint OriginalTtl,
    uint SignatureExpiration,
    uint SignatureInception,
    ushort KeyTag,
    DomainLabels SignersName,
    ImmutableArray<byte> Signature
) : IDomainResourceRecordData
{
    private int? _size;
    public int EstimatedSize => _size ??= sizeof(ushort) + sizeof(byte) + sizeof(byte) + 
                                          sizeof(uint) + sizeof(uint) + sizeof(uint) + 
                                          sizeof(ushort) + SignersName.EstimatedSize + Signature.Length;

    public void WriteTo(ref DnsParsingSpan span)
    {
        var origin = span;
        span = span[2..];
        DomainMessageEncoder.EncodeAndAdvance(ref span, (ushort)TypeCovered);
        DomainMessageEncoder.EncodeAndAdvance(ref span, (byte)Algorithm);
        DomainMessageEncoder.EncodeAndAdvance(ref span, Labels);
        
        // Use custom encoding for uint/network byte order since standard EncodeAndAdvance uses int for 4 bytes.
        BitConverter.TryWriteBytes(span, ((int)OriginalTtl).ToNetworkByteOrder());
        span = span[4..];
        BitConverter.TryWriteBytes(span, ((int)SignatureExpiration).ToNetworkByteOrder());
        span = span[4..];
        BitConverter.TryWriteBytes(span, ((int)SignatureInception).ToNetworkByteOrder());
        span = span[4..];

        DomainMessageEncoder.EncodeAndAdvance(ref span, KeyTag);
        
        // RRSIG Signer's Name MUST NOT be compressed according to RFC 4034 Section 3.1.7.
        // We bypass DomainMessageEncoder.EncodeAndAdvance(ref DnsParsingSpan, DomainLabels) 
        // to avoid compression logic.
        foreach (var label in SignersName.Labels)
        {
            DomainMessageEncoder.EncodeAndAdvance(ref span, label);
        }
        DomainMessageEncoder.EncodeAndAdvance(ref span, (byte)0); // Root label

        Signature.CopyTo(span);
        span = span[Signature.Length..];
        DomainMessageEncoder.EncodeAndAdvance(ref origin, (ushort)(span.Offset - (origin.Offset + 2)));
    }

    public static IDomainResourceRecordData ReadFrom(ref ReadOnlyDnsParsingSpan bytes, int dataLength)
    {
        var startOffset = bytes.Offset;
        var typeCovered = (DomainRecordType)DomainMessageEncoder.ReadUnsignedShortAndAdvance(ref bytes);
        var algorithm = (DnssecAlgorithmType)DomainMessageEncoder.ReadByteAndAdvance(ref bytes);
        var labels = DomainMessageEncoder.ReadByteAndAdvance(ref bytes);
        
        // Read uints
        var origTtl = (uint)DomainMessageEncoder.ReadIntegerAndAdvance(ref bytes);
        var sigExp = (uint)DomainMessageEncoder.ReadIntegerAndAdvance(ref bytes);
        var sigInc = (uint)DomainMessageEncoder.ReadIntegerAndAdvance(ref bytes);
        
        var keyTag = DomainMessageEncoder.ReadUnsignedShortAndAdvance(ref bytes);
        
        var signersName = DomainMessageEncoder.ReadLabelsAndAdvance(ref bytes);
        
        var parsedSoFar = bytes.Offset - startOffset;
        var signatureLength = dataLength - parsedSoFar;
        var signatureData = bytes.CurrentSpan[..signatureLength].ToImmutableArray();
        bytes = bytes[signatureLength..];
        
        return new ResourceRecordSignatureData(
            typeCovered, algorithm, labels, origTtl, sigExp, sigInc, keyTag, signersName, signatureData);
    }
}