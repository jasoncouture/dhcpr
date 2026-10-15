using System.Collections.Concurrent;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Zone;

namespace Dhcpr.Dns.Core.Resolvers.Caching;

/// <summary>
/// Zones whose nameservers could not be reached. Names at or below the cut fail
/// without another referral walk until the entry expires.
/// </summary>
public interface IUnreachableAuthorityCache
{
    void Remember(string zone);
    bool Contains(DomainLabels name);
}

public sealed class UnreachableAuthorityCache : IUnreachableAuthorityCache
{
    public static readonly TimeSpan Ttl = TimeSpan.FromSeconds(60);

    private readonly ConcurrentDictionary<string, long> _untilTicks =
        new(StringComparer.OrdinalIgnoreCase);

    public void Remember(string zone)
    {
        var normalized = RootZoneSnapshot.NormalizeOwner(zone);
        if (normalized.Length == 0)
            return;

        var until = DateTimeOffset.UtcNow.Add(Ttl).UtcTicks;
        _untilTicks.AddOrUpdate(normalized, until, (_, existing) => Math.Max(existing, until));
    }

    public bool Contains(DomainLabels name)
    {
        var current = RootZoneSnapshot.NormalizeOwner(name.ToString());
        var now = DateTimeOffset.UtcNow.UtcTicks;
        while (current.Length > 0)
        {
            if (_untilTicks.TryGetValue(current, out var until))
            {
                if (now <= until)
                    return true;
                _untilTicks.TryRemove(current, out _);
            }

            var dot = current.IndexOf('.');
            if (dot < 0)
                break;
            current = current[(dot + 1)..];
        }

        return false;
    }
}
