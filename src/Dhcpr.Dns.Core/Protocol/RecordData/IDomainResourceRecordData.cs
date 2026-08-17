using Dhcpr.Dns.Core.Protocol.Parser;

namespace Dhcpr.Dns.Core.Protocol.RecordData;

public interface IDomainResourceRecordData : ISelfComputeEstimatedSize
{
    /// <summary>
    /// Writes this RDATA (including RDLENGTH) to <paramref name="span"/>.
    /// </summary>
    void WriteTo(ref DnsParsingSpan span);

    /// <summary>
    /// Parses RDATA of <paramref name="dataLength"/> bytes from <paramref name="bytes"/>.
    /// </summary>
    static abstract IDomainResourceRecordData ReadFrom(ref ReadOnlyDnsParsingSpan bytes, int dataLength);
}