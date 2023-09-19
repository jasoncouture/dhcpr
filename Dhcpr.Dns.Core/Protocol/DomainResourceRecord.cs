using System.Collections.Immutable;

using Dhcpr.Dns.Core.Protocol.RecordData;

namespace Dhcpr.Dns.Core.Protocol;

public sealed record DomainResourceRecord(
    DomainLabels Name,
    DomainRecordType Type,
    DomainRecordClass Class,
    TimeSpan TimeToLive,
    IDomainResourceRecordData Data
) : ISelfComputeEstimatedSize
{
    private int? _size;
    public int EstimatedSize => _size ??= Name.EstimatedSize + sizeof(ushort) + sizeof(ushort) + sizeof(int) + sizeof(ushort) + Data.EstimatedSize;
}