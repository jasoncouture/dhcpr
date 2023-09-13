using Dhcpr.Dns.Core.Protocol.Parser;

namespace Dhcpr.Dns.Core.Protocol.RecordData;

public record NameData(DomainLabels Name) : IDomainResourceRecordData
{
    public int Size => Name.Size;

    public void WriteTo(ref DnsParsingSpan span) => DomainMessageEncoder.EncodeAndAdvance(ref span, Name);

    public static IDomainResourceRecordData ReadFrom(ReadOnlyDnsParsingSpan bytes) => new NameData(DomainMessageEncoder.ReadLabelsAndAdvance(ref bytes));
}