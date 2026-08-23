using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Net;

using Dhcpr.Dns.Core.Protocol;

namespace Dhcpr.Dns.Core.Protocol.Processing;

/// <summary>
/// Query-scoped zone-cut endpoints shared with CNAME/glue re-entries.
/// Directed hops bypass the response cache; this remembers NS addresses
/// already learned so later aliases do not restart at the root.
/// </summary>
public sealed class NameserverTipCache
{
    private readonly ConcurrentDictionary<string, ImmutableArray<IPEndPoint>> _tips =
        new(StringComparer.OrdinalIgnoreCase);

    public void Remember(string zone, IEnumerable<IPEndPoint> endpoints)
    {
        var list = endpoints.ToImmutableArray();
        if (list.Length == 0)
            return;
        _tips[Normalize(zone)] = list;
    }

    public bool TryGetClosest(
        DomainLabels name,
        out ImmutableArray<IPEndPoint> tips,
        out DomainLabels zone)
    {
        var labels = name.Labels;
        for (var skip = 0; skip < labels.Length; skip++)
        {
            var suffix = new DomainLabels(labels[skip..]);
            var key = Normalize(suffix.ToString());
            if (key.Length == 0)
                continue;
            if (!_tips.TryGetValue(key, out tips))
                continue;
            zone = suffix;
            return true;
        }

        tips = default;
        zone = DomainLabels.Empty;
        return false;
    }

    private static string Normalize(string zone) => zone.Trim().TrimEnd('.');
}
