using System;
using System.Collections.Immutable;
using Dhcpr.Dns.Core.Protocol.RecordData;

namespace Dhcpr.Dns.Core.Protocol;

public interface IEdnsProtocolService
{
    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="record"/> is an OPT with the DO (DNSSEC OK) bit set.
    /// </summary>
    bool IsDnssecOk(DomainResourceRecord record);

    /// <summary>
    /// Returns the advertised UDP payload size from an OPT record's CLASS field.
    /// </summary>
    ushort GetUdpPayloadSize(DomainResourceRecord record);

    /// <summary>
    /// Returns the extended RCODE from the high byte of an OPT record's TTL.
    /// </summary>
    byte GetExtendedRCode(DomainResourceRecord record);

    /// <summary>
    /// Returns the EDNS version from bits 16–23 of an OPT record's TTL.
    /// </summary>
    byte GetEdnsVersion(DomainResourceRecord record);

    /// <summary>
    /// Builds an OPT record with the given payload size, DO bit, extended RCODE, version, and option data.
    /// </summary>
    DomainResourceRecord CreateOptRecord(ushort udpPayloadSize, bool dnssecOk = false, byte extendedRCode = 0, byte version = 0, OptionData? optData = null);
}
