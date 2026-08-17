using System.Collections.Immutable;

using Dhcpr.Dns.Core.Protocol;

namespace Dhcpr.Dns.Core.Authoritative;

/// <summary>Mutable builder node; freeze into <see cref="ImmutableLabelTreeNode"/> on publish.</summary>
internal sealed class LabelTreeNode
{
    public Dictionary<string, LabelTreeNode> Children { get; } = new(StringComparer.OrdinalIgnoreCase);
    public List<DomainResourceRecord> Records { get; } = [];
    public bool HasNs { get; set; }
    public AuthoritativeZone? Zone { get; set; }

    public LabelTreeNode GetOrAddChild(string label)
    {
        if (!Children.TryGetValue(label, out var child))
        {
            child = new LabelTreeNode();
            Children[label] = child;
        }

        return child;
    }

    public ImmutableLabelTreeNode ToImmutable()
    {
        var children = Children.ToImmutableDictionary(
            static kv => kv.Key.ToLowerInvariant(),
            static kv => kv.Value.ToImmutable(),
            StringComparer.OrdinalIgnoreCase);

        return new ImmutableLabelTreeNode(
            children,
            Records.ToImmutableArray(),
            HasNs,
            Zone);
    }
}
