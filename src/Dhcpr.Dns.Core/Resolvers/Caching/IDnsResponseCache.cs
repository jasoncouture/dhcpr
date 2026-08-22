using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;

namespace Dhcpr.Dns.Core.Resolvers.Caching;

public interface IDnsResponseCache
{
    /// <summary>
    /// Looks up a cached response for <paramref name="request"/>, ignoring stored DNSSEC status.
    /// </summary>
    /// <returns><see langword="true"/> when a non-expired entry exists.</returns>
    bool TryGet(DomainMessage request, out DomainMessage? response);

    /// <summary>
    /// Looks up a cached response and its stored <see cref="DnssecValidationStatus"/>.
    /// Cached messages never resurrect the AD bit; callers apply AD from <paramref name="securityStatus"/>.
    /// </summary>
    /// <returns><see langword="true"/> when a non-expired entry exists.</returns>
    bool TryGet(DomainMessage request, out DomainMessage? response, out DnssecValidationStatus securityStatus);

    /// <summary>
    /// Stores <paramref name="response"/> for <paramref name="request"/>. Implementations may skip
    /// truncated, SERVFAIL, REFUSED, Bogus, or referral answers.
    /// </summary>
    void Set(DomainMessage request, DomainMessage response, DnssecValidationStatus securityStatus = DnssecValidationStatus.Unchecked);

    /// <summary>
    /// Overwrites the stored DNSSEC status for <paramref name="request"/>.
    /// A <see cref="DnssecValidationStatus.Bogus"/> status removes the entry.
    /// </summary>
    void UpdateSecurityStatus(DomainMessage request, DnssecValidationStatus securityStatus);

    /// <summary>
    /// Drops the cached entry for <paramref name="request"/>, if any.
    /// </summary>
    void Remove(DomainMessage request);

    /// <summary>
    /// Removes every cached entry.
    /// </summary>
    void Clear();

    /// <summary>
    /// Applies a replica fill without publishing another cluster event.
    /// </summary>
    void Import(
        DomainMessage request,
        DomainMessage response,
        DnssecValidationStatus securityStatus,
        DateTimeOffset cachedAt);

    /// <summary>
    /// Applies a replica DNSSEC status without publishing another cluster event.
    /// </summary>
    void ImportSecurityStatus(DomainMessage request, DnssecValidationStatus securityStatus);

    /// <summary>
    /// Applies a replica clear without publishing another cluster event.
    /// </summary>
    void ImportClear();
}
