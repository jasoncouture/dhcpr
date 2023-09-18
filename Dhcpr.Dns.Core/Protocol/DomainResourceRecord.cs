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
    public int EstimatedSize => _size ??= Name.EstimatedSize + sizeof(ushort) + sizeof(ushort) + sizeof(int) + 1 + Data.Length;
    public ushort DataLogicalSize => GetDataSizeForType(Type);
    
    private ushort GetDataSizeForType(DomainRecordType type)
    {
        return type switch
        {
            DomainRecordType.A => 1,
            DomainRecordType.AAAA => 1,
            _ => (ushort)Data.Length
        };
    }

    public IDomainResourceRecordData RecordData => _recordData ??= Data.AsSpan().ToData(Type);
}