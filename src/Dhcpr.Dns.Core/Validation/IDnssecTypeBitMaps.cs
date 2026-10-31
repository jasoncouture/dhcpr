using System.Collections.Immutable;

using Dhcpr.Dns.Core.Protocol;

namespace Dhcpr.Dns.Core.Validation;

/// <summary>
/// RFC 4034 §4.1.2 / RFC 5155 type bit maps for NSEC / NSEC3.
/// </summary>
public interface IDnssecTypeBitMaps
{
    bool Contains(ImmutableArray<byte> typeBitMaps, DomainRecordType type);

    ImmutableArray<byte> FromTypes(params DomainRecordType[] types);
}
