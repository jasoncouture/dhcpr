using System.Collections.Immutable;

using Dhcpr.Dns.Core.Protocol;

namespace Dhcpr.Dns.Core.Authoritative;

public sealed class ImmutableLabelTreeNode
{
    public ImmutableLabelTreeNode(
        ImmutableDictionary<string, ImmutableLabelTreeNode> children,
        ImmutableArray<DomainResourceRecord> records,
        bool hasNs,
        AuthoritativeZone? zone)
    {
        Children = children;
        Records = records;
        HasNs = hasNs;
        Zone = zone;
    }

    public ImmutableDictionary<string, ImmutableLabelTreeNode> Children { get; }
    public ImmutableArray<DomainResourceRecord> Records { get; }
    public bool HasNs { get; }
    public AuthoritativeZone? Zone { get; }

    public bool TryGetChild(string label, out ImmutableLabelTreeNode child)
        => Children.TryGetValue(label, out child!);

    public bool HasChildren => Children.Count > 0;
}
