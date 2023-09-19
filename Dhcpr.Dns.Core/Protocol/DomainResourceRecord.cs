using System.Collections.Immutable;

using Dhcpr.Dns.Core.Protocol.RecordData;

namespace Dhcpr.Dns.Core.Protocol;

public sealed record DomainResourceRecord(
    DomainLabels Name,
    DomainRecordType Type,
    DomainRecordClass Class,
    TimeSpan TimeToLive,
    ImmutableArray<byte> Data
) : ISelfComputeEstimatedSize
{
    private IDomainResourceRecordData? _recordData;
    private int? _size;
    public int EstimatedSize => _size ??= Name.EstimatedSize + sizeof(ushort) + sizeof(ushort) + sizeof(int) + sizeof(ushort) + Data.Length;

    public IDomainResourceRecordData RecordData => _recordData ??= Data.AsSpan().ToData(Type);
}