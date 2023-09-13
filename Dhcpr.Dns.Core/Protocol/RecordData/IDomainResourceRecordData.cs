using Dhcpr.Dns.Core.Protocol.Parser;

namespace Dhcpr.Dns.Core.Protocol.RecordData;

public interface IDomainResourceRecordData : ISelfComputeEstimatedSize
{
    void WriteTo(ref DnsParsingSpan span);
    static abstract IDomainResourceRecordData ReadFrom(ReadOnlyDnsParsingSpan bytes);
}