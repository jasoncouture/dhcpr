using System;
using System.Collections.Immutable;
using Dhcpr.Dns.Core.Protocol.RecordData;

namespace Dhcpr.Dns.Core.Protocol;

public interface IEdnsProtocolService
{
    bool IsDnssecOk(DomainResourceRecord record);
    ushort GetUdpPayloadSize(DomainResourceRecord record);
    byte GetExtendedRCode(DomainResourceRecord record);
    byte GetEdnsVersion(DomainResourceRecord record);
    DomainResourceRecord CreateOptRecord(ushort udpPayloadSize, bool dnssecOk = false, byte extendedRCode = 0, byte version = 0, OptData? optData = null);
}
