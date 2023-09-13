using Dhcpr.Dns.Core.Protocol.Parser;

namespace Dhcpr.Dns.Core.Protocol.RecordData;

public sealed record StartOfAuthorityData(
    int SerialNumber,
    TimeSpan RefreshInterval,
    TimeSpan RetryInterval,
    TimeSpan ExpireInterval,
    TimeSpan MinimumTimeToLive
) : IDomainResourceRecordData
{
    public int Size => 5 * sizeof(int);

    public void WriteTo(ref DnsParsingSpan span)
    {
        DomainMessageEncoder.EncodeAndAdvance(ref span, SerialNumber);
        DomainMessageEncoder.EncodeAndAdvance(ref span, RefreshInterval);
        DomainMessageEncoder.EncodeAndAdvance(ref span, RetryInterval);
        DomainMessageEncoder.EncodeAndAdvance(ref span, ExpireInterval);
        DomainMessageEncoder.EncodeAndAdvance(ref span, MinimumTimeToLive);
    }

    public static IDomainResourceRecordData ReadFrom(ReadOnlyDnsParsingSpan bytes)
    {
        var serialNumber = DomainMessageEncoder.ReadIntegerAndAdvance(ref bytes);
        var refreshInterval = DomainMessageEncoder.ReadIntegerAndAdvance(ref bytes);
        var retryInterval = DomainMessageEncoder.ReadIntegerAndAdvance(ref bytes);
        var expireInterval = DomainMessageEncoder.ReadIntegerAndAdvance(ref bytes);
        var minimumTimeToLive = DomainMessageEncoder.ReadIntegerAndAdvance(ref bytes);
        return new StartOfAuthorityData(
            serialNumber,
            TimeSpan.FromSeconds(refreshInterval),
            TimeSpan.FromSeconds(retryInterval),
            TimeSpan.FromSeconds(expireInterval),
            TimeSpan.FromSeconds(minimumTimeToLive)
        );
    }
}