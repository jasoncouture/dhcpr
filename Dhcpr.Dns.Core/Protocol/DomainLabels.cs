using System.Collections;
using System.Collections.Immutable;

using Dhcpr.Core;

namespace Dhcpr.Dns.Core.Protocol;

public sealed record DomainLabels(ImmutableArray<DomainLabel> Labels) : ISelfComputeEstimatedSize, IReadOnlyList<string>
{
    private static IEnumerable<DomainLabel> ValidateAndCreateLabelsFromStrings(IEnumerable<string> strings)
    {
        foreach (var str in strings.Select(i => i.Trim()))
        {
            if (!str.IsValidDomainNameLabel())
                throw new InvalidOperationException($"Invalid domain name label: \"{str}\"");
            yield return new DomainLabel(str);
        }
    }

    public DomainLabels(string str) : this(str.TrimEnd('.').Split('.')) { }

    public DomainLabels(IEnumerable<string> strings) : this(ValidateAndCreateLabelsFromStrings(strings)
        .ToImmutableArray())
    {
    }

    private string? _domainName;
    private int? _size;
    public int EstimatedSize => _size ??= Labels.Select(i => i.EstimatedSize).Sum() + 1;
    private string DomainName => _domainName ??= FormatDomainName(Labels);

    public static DomainLabels Empty { get; } = new DomainLabels(ImmutableArray<DomainLabel>.Empty);

    private static string FormatDomainName(ImmutableArray<DomainLabel> labels)
        => string.Join(".", labels);

    public IEnumerator<string> GetEnumerator()
    {
        return Labels.Select(i => i.Label).GetEnumerator();
    }

    public override string ToString()
        => DomainName;

    IEnumerator IEnumerable.GetEnumerator()
    {
        return GetEnumerator();
    }

    public int Count => Labels.Length;

    public string this[int index] => Labels[index].Label;
}