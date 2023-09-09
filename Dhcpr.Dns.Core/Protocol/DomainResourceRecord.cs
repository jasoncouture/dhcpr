﻿using System.Collections.Immutable;

namespace Dhcpr.Dns.Core.Protocol;

public sealed record DomainResourceRecord(
    DomainLabels Name,
    DomainRecordType Type,
    DomainRecordClass Class,
    TimeSpan TimeToLive,
    ImmutableArray<byte> Data
) : ISelfComputeSize
{
    private IDomainResourceRecordData? _recordData;
    private int? _size;
    public int Size => _size ??= Name.Size + sizeof(ushort) + sizeof(ushort) + sizeof(int) + 1 + Data.Length;
    public IDomainResourceRecordData RecordData => _recordData ??= Data.AsSpan().ToData(Type);
}