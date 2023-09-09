namespace Dhcpr.Dns.Core.Protocol;

public record NameData(DomainLabels Name) : IDomainResourceRecordData
{
    public int Size => Name.Size;

    public void WriteTo(ref Span<byte> span) => DomainMessageEncoder.EncodeAndAdvance(ref span, Name);

    public static IDomainResourceRecordData ReadFrom(ReadOnlySpan<byte> bytes) => new NameData(DomainMessageEncoder.ReadLabelsAndAdvance(ref bytes));
}