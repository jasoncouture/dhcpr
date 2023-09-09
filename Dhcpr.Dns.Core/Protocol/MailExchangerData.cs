namespace Dhcpr.Dns.Core.Protocol;

public sealed record MailExchangerData(ushort Preference, DomainLabels ExchangerName) : IDomainResourceRecordData
{
    public void WriteTo(ref Span<byte> span)
    {
        DomainMessageEncoder.EncodeAndAdvance(ref span, Preference);
        DomainMessageEncoder.EncodeAndAdvance(ref span, ExchangerName);
    }

    public static IDomainResourceRecordData ReadFrom(ReadOnlySpan<byte> bytes)
    {
        return new MailExchangerData(
            DomainMessageEncoder.ReadUnsignedShortAndAdvance(ref bytes),
            DomainMessageEncoder.ReadLabelsAndAdvance(ref bytes)
        );
    }

    public int Size => sizeof(ushort) + ExchangerName.Size;
}