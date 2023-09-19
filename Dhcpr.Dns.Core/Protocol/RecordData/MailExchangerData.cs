using Dhcpr.Dns.Core.Protocol.Parser;

namespace Dhcpr.Dns.Core.Protocol.RecordData;

public sealed record MailExchangerData(ushort Preference, DomainLabels ExchangerName) : IDomainResourceRecordData
{
    public void WriteTo(ref DnsParsingSpan span)
    {
        var origin = span;
        span = span[2..];
        DomainMessageEncoder.EncodeAndAdvance(ref span, Preference);
        DomainMessageEncoder.EncodeAndAdvance(ref span, ExchangerName);
        // When we're writing labels, we can't really know the size in advance due to label compression
        // So we jump back here and write the length after writing the rest of the data to determine
        // the size.
        DomainMessageEncoder.EncodeAndAdvance(ref origin, (ushort)(span.Offset - (origin.Offset + 2)));
    }

    public static IDomainResourceRecordData ReadFrom(ref ReadOnlyDnsParsingSpan bytes, int dataLength)
    {
        return new MailExchangerData(
            DomainMessageEncoder.ReadUnsignedShortAndAdvance(ref bytes),
            DomainMessageEncoder.ReadLabelsAndAdvance(ref bytes)
        );
    }

    public int EstimatedSize => sizeof(ushort) + ExchangerName.EstimatedSize;
}