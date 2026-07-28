using System.Collections.Immutable;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Zone;

namespace Dhcpr.Dns.Core.Authoritative;

public sealed class AuthoritativeZoneStore
{
    private ImmutableLabelTreeNode _root = new(
        ImmutableDictionary<string, ImmutableLabelTreeNode>.Empty,
        ImmutableArray<DomainResourceRecord>.Empty,
        hasNs: false,
        zone: null);

    public void Publish(IReadOnlyList<AuthoritativeZone> zones)
    {
        var builder = new LabelTreeNode();
        foreach (var zone in zones)
        {
            var node = builder;
            for (var i = zone.ApexLabels.Length - 1; i >= 0; i--)
                node = node.GetOrAddChild(zone.ApexLabels[i]);

            if (node.Zone is not null)
                continue; // first wins; caller logs duplicates

            node.Zone = zone;
        }

        Volatile.Write(ref _root, builder.ToImmutable());
    }

    public AuthoritativeZone? FindZone(string qname)
    {
        var owner = RootZoneSnapshot.NormalizeOwner(qname);
        var labels = owner.Length == 0 ? Array.Empty<string>() : owner.Split('.');
        var current = Volatile.Read(ref _root);
        AuthoritativeZone? best = current.Zone;

        for (var i = labels.Length - 1; i >= 0; i--)
        {
            if (!current.TryGetChild(labels[i], out var next))
                break;
            current = next;
            if (current.Zone is not null)
                best = current.Zone;
        }

        return best;
    }

    public AuthoritativeZone? FindZoneExactApex(string apex)
    {
        var owner = RootZoneSnapshot.NormalizeOwner(apex);
        var labels = owner.Length == 0 ? Array.Empty<string>() : owner.Split('.');
        var current = Volatile.Read(ref _root);

        for (var i = labels.Length - 1; i >= 0; i--)
        {
            if (!current.TryGetChild(labels[i], out var next))
                return null;
            current = next;
        }

        return current.Zone;
    }
}
