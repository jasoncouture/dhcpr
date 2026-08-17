using System.Collections.Immutable;

using Dhcpr.Dns.Core.Protocol.RecordData;

namespace Dhcpr.Dns.Core.Protocol.Processing;

/// <summary>Authenticated DS set (or trust-anchor equivalent) for a child zone.</summary>
public sealed class AuthenticatedDelegation
{
    public required string Zone { get; init; }
    public required ImmutableArray<DelegationSignerData> Digests { get; init; }
    /// <summary>True when this is a configured trust anchor, not a fetched DS RRset.</summary>
    public bool IsTrustAnchor { get; init; }
}
