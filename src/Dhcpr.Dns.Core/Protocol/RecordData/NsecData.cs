using System.Collections.Immutable;
using Dhcpr.Dns.Core.Protocol.Parser;

namespace Dhcpr.Dns.Core.Protocol.RecordData;

public sealed record NsecData(
    DomainLabels NextDomainName,
    ImmutableArray<byte> TypeBitMaps
) : IDomainResourceRecordData
{
    private int? _size;
    public int EstimatedSize => _size ??= NextDomainName.EstimatedSize + TypeBitMaps.Length;

    public void WriteTo(ref DnsParsingSpan span)
    {
        var origin = span;
        span = span[2..];
        // RFC 4034 4.1.1: The Next Domain Name field is not compressed.
        foreach (var label in NextDomainName.Labels)
        {
            DomainMessageEncoder.EncodeAndAdvance(ref span, label);
        }
        DomainMessageEncoder.EncodeAndAdvance(ref span, (byte)0); // Root label

        TypeBitMaps.CopyTo(span);
        span = span[TypeBitMaps.Length..];
        DomainMessageEncoder.EncodeAndAdvance(ref origin, (ushort)(span.Offset - (origin.Offset + 2)));
    }

    public static IDomainResourceRecordData ReadFrom(ref ReadOnlyDnsParsingSpan bytes, int dataLength)
    {
        var startOffset = bytes.Offset;
        var nextDomainName = DomainMessageEncoder.ReadLabelsAndAdvance(ref bytes);
        
        var parsedSoFar = bytes.Offset - startOffset;
        var mapLength = dataLength - parsedSoFar;
        var typeBitMaps = bytes.CurrentSpan[..mapLength].ToImmutableArray();
        bytes = bytes[mapLength..];
        
        return new NsecData(nextDomainName, typeBitMaps);
    }
}
