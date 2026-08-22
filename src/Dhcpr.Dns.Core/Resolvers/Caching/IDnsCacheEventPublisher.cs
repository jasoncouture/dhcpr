using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;

namespace Dhcpr.Dns.Core.Resolvers.Caching;

/// <summary>
/// Cluster fan-out for local cache mutations. Implementations must not block the DNS path.
/// </summary>
public interface IDnsCacheEventPublisher
{
    /// <summary>Identifies this process so replica apply can skip the origin echo.</summary>
    Guid OriginId { get; }

    void PublishSet(
        DomainMessage request,
        DomainMessage response,
        DnssecValidationStatus securityStatus,
        DateTimeOffset cachedAt);

    void PublishSecurityStatus(DomainMessage request, DnssecValidationStatus securityStatus);

    void PublishClear();
}
