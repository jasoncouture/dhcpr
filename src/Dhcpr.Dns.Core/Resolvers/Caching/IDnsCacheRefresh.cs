using Dhcpr.Dns.Core.Protocol.Processing;

namespace Dhcpr.Dns.Core.Resolvers.Caching;

/// <summary>
/// Starts a background refresh of a cache entry that is about to expire.
/// The hit path must not wait for it.
/// </summary>
public interface IDnsCacheRefresh
{
    void Schedule(DomainMessageContext context);
}
