using System.Collections;
using System.Collections.Immutable;

namespace Dhcpr.Dhcp.Core.Protocol;

public sealed record DhcpOptionCollection(ImmutableArray<DhcpOption> Options) : IEnumerable<DhcpOption>
{
    private int? _length;
    public int Length => _length ??= Options.Select(i => i.Length).DefaultIfEmpty(0).Sum(i => i);

    public IEnumerator<DhcpOption> GetEnumerator()
    {
        return Options.AsEnumerable().GetEnumerator();
    }

    public override string ToString()
    {
        return string.Concat($"{{ {Environment.NewLine}", string.Join($",{Environment.NewLine}", Options.Select(i => $"\t{i.ToString()}")), $"{Environment.NewLine}}}");
    }

    IEnumerator IEnumerable.GetEnumerator()
    {
        return GetEnumerator();
    }
}