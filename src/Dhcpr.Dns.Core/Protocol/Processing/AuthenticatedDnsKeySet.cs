using System.Collections.Immutable;

using Dhcpr.Dns.Core.Protocol;

namespace Dhcpr.Dns.Core.Protocol.Processing;

/// <summary>Authenticated DNSKEY set for a zone apex.</summary>
public sealed class AuthenticatedDnsKeySet
{
    public required string Zone { get; init; }
    public required ImmutableArray<DomainResourceRecord> Keys { get; init; }
}
