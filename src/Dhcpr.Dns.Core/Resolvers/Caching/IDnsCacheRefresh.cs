using Dhcpr.Dns.Core.Protocol.Processing;

namespace Dhcpr.Dns.Core.Resolvers.Caching;

/// <summary>
/// Fetches a fresh response for a cache entry that is about to expire.
/// </summary>
public interface IDnsCacheRefresh
{
    Task RefreshAsync(DomainMessageContext context);
}
