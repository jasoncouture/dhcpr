namespace Dhcpr.Dns.Core.Resolvers.Caching;

/// <summary>
/// Names currently being refreshed. Shared by every query scope.
/// </summary>
public interface IDnsCacheRefreshTracker
{
    bool TryAdd(DnsCacheKey key);

    void Remove(DnsCacheKey key);
}
