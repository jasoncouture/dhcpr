using Dhcpr.Dns.Core.Protocol.Parser;

namespace Dhcpr.Dns.Core.Protocol.RecordData;

public record ServiceData(ushort Priority, ushort Weight, ushort Port, DomainLabels Name) : IDomainResourceRecordData
{
    public int EstimatedSize => (sizeof(ushort) * 3) + Name.EstimatedSize;
    public void WriteTo(ref DnsParsingSpan span)
    {
        var origin = span;
        span = span[2..];
        DomainMessageEncoder.EncodeAndAdvance(ref span, Priority);
        DomainMessageEncoder.EncodeAndAdvance(ref span, Weight);
        DomainMessageEncoder.EncodeAndAdvance(ref span, Port);
        DomainMessageEncoder.EncodeAndAdvance(ref span, Name);
        var length = span.Offset - (origin.Offset + 2);
        DomainMessageEncoder.EncodeAndAdvance(ref origin, (ushort)length);
    }

    public static IDomainResourceRecordData ReadFrom(ref ReadOnlyDnsParsingSpan bytes, int dataLength)
    {
        var priority = DomainMessageEncoder.ReadUnsignedShortAndAdvance(ref bytes);
        var weight = DomainMessageEncoder.ReadUnsignedShortAndAdvance(ref bytes);
        var port = DomainMessageEncoder.ReadUnsignedShortAndAdvance(ref bytes);
        var name = DomainMessageEncoder.ReadLabelsAndAdvance(ref bytes);
        return new ServiceData(priority, weight, port, name);
    }
}