using Dhcpr.Dns.Core.Protocol;

namespace Dhcpr.Dns.Core.Validation;

public enum TrustAnchorRefreshKind
{
    NotAuthenticated,
    Unchanged,
    Updated
}

public sealed class TrustAnchorRefreshOutcome
{
    public TrustAnchorRefreshKind Kind { get; init; }
    public IReadOnlyList<TrustAnchorEvent> Events { get; init; } = [];
}

public interface ITrustAnchorStore
{
    TrustAnchorConfiguration[] GetActiveAnchors();

    /// <summary>
    /// Apply RFC 5011 to a root DNSKEY RRset. New keys are ignored unless a key this store
    /// already trusts signed the set.
    /// </summary>
    ValueTask<TrustAnchorRefreshOutcome> AcceptDnsKeySetAsync(
        IReadOnlyList<DomainResourceRecord> dnsKeys,
        IReadOnlyList<DomainResourceRecord> rrsigs,
        IDnssecValidator crypto,
        DateTimeOffset now,
        CancellationToken cancellationToken);
}
