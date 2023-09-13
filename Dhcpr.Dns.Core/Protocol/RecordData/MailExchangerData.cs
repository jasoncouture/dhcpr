using Dhcpr.Dns.Core.Protocol.Parser;

namespace Dhcpr.Dns.Core.Protocol.RecordData;

public sealed record MailExchangerData(ushort Preference, DomainLabels ExchangerName) : IDomainResourceRecordData
{
    public void WriteTo(ref DnsParsingSpan span)
    {
        DomainMessageEncoder.EncodeAndAdvance(ref span, Preference);
        DomainMessageEncoder.EncodeAndAdvance(ref span, ExchangerName);
    }

    public static IDomainResourceRecordData ReadFrom(ReadOnlyDnsParsingSpan bytes)
    {
        return new MailExchangerData(
            DomainMessageEncoder.ReadUnsignedShortAndAdvance(ref bytes),
            DomainMessageEncoder.ReadLabelsAndAdvance(ref bytes)
        );
    }

    public int Size => sizeof(ushort) + ExchangerName.Size;
}