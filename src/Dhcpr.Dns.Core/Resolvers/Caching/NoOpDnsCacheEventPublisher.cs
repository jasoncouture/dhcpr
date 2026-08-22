using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;

namespace Dhcpr.Dns.Core.Resolvers.Caching;

/// <summary>
/// Default publisher when the host does not register a cluster sink.
/// </summary>
public sealed class NoOpDnsCacheEventPublisher : IDnsCacheEventPublisher
{
    public static NoOpDnsCacheEventPublisher Instance { get; } = new();

    public Guid OriginId => Guid.Empty;

    public void PublishSet(
        DomainMessage request,
        DomainMessage response,
        DnssecValidationStatus securityStatus,
        DateTimeOffset cachedAt)
    {
    }

    public void PublishSecurityStatus(DomainMessage request, DnssecValidationStatus securityStatus)
    {
    }

    public void PublishClear()
    {
    }
}
