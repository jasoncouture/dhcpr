using System.Collections.Concurrent;

namespace Dhcpr.Dns.Core.Resolvers.Caching;

/// <summary>
/// One in-flight set for the process, so two queries do not both refresh the same name.
/// </summary>
public sealed class DnsCacheRefreshTracker : IDnsCacheRefreshTracker
{
    private readonly ConcurrentDictionary<DnsCacheKey, byte> _refreshing = new();

    public bool TryAdd(DnsCacheKey key) => _refreshing.TryAdd(key, 0);

    public void Remove(DnsCacheKey key) => _refreshing.TryRemove(key, out _);
}
