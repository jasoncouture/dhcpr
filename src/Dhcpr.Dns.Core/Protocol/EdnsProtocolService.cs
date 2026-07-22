using System;
using System.Collections.Immutable;
using Dhcpr.Dns.Core.Protocol.RecordData;

namespace Dhcpr.Dns.Core.Protocol;

public sealed class EdnsProtocolService : IEdnsProtocolService
{
    private const int DnssecOkBit = 0x8000;

    public bool IsDnssecOk(DomainResourceRecord record)
    {
        if (record.Type != DomainRecordType.OPT) return false;
        var ttl = (int)record.TimeToLive.TotalSeconds;
        return (ttl & DnssecOkBit) != 0;
    }

    public ushort GetUdpPayloadSize(DomainResourceRecord record)
    {
        if (record.Type != DomainRecordType.OPT) return 0;
        return (ushort)record.Class;
    }

    public byte GetExtendedRCode(DomainResourceRecord record)
    {
        if (record.Type != DomainRecordType.OPT) return 0;
        var ttl = (int)record.TimeToLive.TotalSeconds;
        return (byte)((ttl >> 24) & 0xFF);
    }

    public byte GetEdnsVersion(DomainResourceRecord record)
    {
        if (record.Type != DomainRecordType.OPT) return 0;
        var ttl = (int)record.TimeToLive.TotalSeconds;
        return (byte)((ttl >> 16) & 0xFF);
    }

    public DomainResourceRecord CreateOptRecord(ushort udpPayloadSize, bool dnssecOk = false, byte extendedRCode = 0, byte version = 0, OptData? optData = null)
    {
        int ttl = (extendedRCode << 24) | (version << 16);
        if (dnssecOk) ttl |= DnssecOkBit;

        return new DomainResourceRecord(
            DomainLabels.Empty,
            DomainRecordType.OPT,
            (DomainRecordClass)udpPayloadSize,
            TimeSpan.FromSeconds(ttl),
            optData ?? new OptData(ImmutableArray<EdnsOption>.Empty)
        );
    }
}
