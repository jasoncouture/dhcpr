using System.Collections;
using System.Collections.Immutable;

using Dhcpr.Core;

namespace Dhcpr.Dns.Core.Protocol;

public sealed record DomainLabels(ImmutableArray<DomainLabel> Labels)
    : ISelfComputeEstimatedSize, IReadOnlyList<string>, IEquatable<DomainLabels>
{
    // ImmutableArray.Equals is reference equality on the backing array — useless for DNS names
    // built from separate parses. Compare the rendered name instead.
    private static IEnumerable<DomainLabel> ValidateAndCreateLabelsFromStrings(IEnumerable<string> strings)
    {
        foreach (var str in strings.Select(i => i.Trim()))
        {
            if (!str.IsValidDomainNameLabel())
                throw new InvalidOperationException($"Invalid domain name label: \"{str}\"");
            yield return new DomainLabel(str);
        }
    }

    // "." and "" are the root. TrimEnd then Split yields one empty string, and an
    // empty string is not a label, so rebuilding the apex from ToString() threw
    // and DNSSEC reported that as Bogus.
    public DomainLabels(string str) : this(LabelsFromPresentation(str)) { }

    private static string[] LabelsFromPresentation(string name)
    {
        var trimmed = name.TrimEnd('.');
        if (trimmed.Length == 0)
            return [];

        return trimmed.Split('.');
    }

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

    public bool Equals(DomainLabels? other)
    {
        if (other is null)
            return false;
        if (ReferenceEquals(this, other))
            return true;
        return string.Equals(DomainName, other.DomainName, StringComparison.OrdinalIgnoreCase);
    }

    public override int GetHashCode()
        => StringComparer.OrdinalIgnoreCase.GetHashCode(DomainName);

    IEnumerator IEnumerable.GetEnumerator()
    {
        return GetEnumerator();
    }

    public int Count => Labels.Length;

    public string this[int index] => Labels[index].Label;
}