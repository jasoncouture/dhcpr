using Dhcpr.Dns.Core.Protocol.Parser;

namespace Dhcpr.Dns.Core.Protocol.RecordData;

public sealed record StartOfAuthorityData(
    DomainLabels MasterName,
    DomainLabels ResponsibleName,
    int SerialNumber,
    TimeSpan RefreshInterval,
    TimeSpan RetryInterval,
    TimeSpan ExpireInterval,
    TimeSpan MinimumTimeToLive
) : IDomainResourceRecordData
{
    private int? _size;
    public int EstimatedSize => _size ??= MasterName.EstimatedSize + ResponsibleName.EstimatedSize + (5 * sizeof(int));

    public void WriteTo(ref DnsParsingSpan span)
    {
        var origin = span;
        span = span[2..];
        DomainMessageEncoder.EncodeAndAdvance(ref span, MasterName);
        DomainMessageEncoder.EncodeAndAdvance(ref span, ResponsibleName);
        DomainMessageEncoder.EncodeAndAdvance(ref span, SerialNumber);
        DomainMessageEncoder.EncodeAndAdvance(ref span, RefreshInterval);
        DomainMessageEncoder.EncodeAndAdvance(ref span, RetryInterval);
        DomainMessageEncoder.EncodeAndAdvance(ref span, ExpireInterval);
        DomainMessageEncoder.EncodeAndAdvance(ref span, MinimumTimeToLive);
        DomainMessageEncoder.EncodeAndAdvance(ref origin, (ushort)(span.Offset - (origin.Offset + 2)));
    }

    public static IDomainResourceRecordData ReadFrom(ref ReadOnlyDnsParsingSpan bytes, int dataLength)
    {
        var masterName = DomainMessageEncoder.ReadLabelsAndAdvance(ref bytes);
        var responsibleName = DomainMessageEncoder.ReadLabelsAndAdvance(ref bytes);
        var serialNumber = DomainMessageEncoder.ReadIntegerAndAdvance(ref bytes);
        var refreshInterval = DomainMessageEncoder.ReadIntegerAndAdvance(ref bytes);
        var retryInterval = DomainMessageEncoder.ReadIntegerAndAdvance(ref bytes);
        var expireInterval = DomainMessageEncoder.ReadIntegerAndAdvance(ref bytes);
        var minimumTimeToLive = DomainMessageEncoder.ReadIntegerAndAdvance(ref bytes);
        return new StartOfAuthorityData(
            masterName,
            responsibleName,
            serialNumber,
            TimeSpan.FromSeconds(refreshInterval),
            TimeSpan.FromSeconds(retryInterval),
            TimeSpan.FromSeconds(expireInterval),
            TimeSpan.FromSeconds(minimumTimeToLive)
        );
    }
}