using System.Collections.Immutable;

using Dhcpr.Core;

namespace Dhcpr.Dns.Core.Protocol;

public sealed record DomainLabels(ImmutableArray<DomainLabel> Labels) : ISelfComputeEstimatedSize
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

    public DomainLabels(string str) : this(str.Split('.')) { }

    public DomainLabels(IEnumerable<string> strings) : this(ValidateAndCreateLabelsFromStrings(strings)
        .ToImmutableArray())
    {
    }

    private string? _domainName;
    private int? _size;
    public int EstimatedSize => _size ??= Labels.Append(DomainLabel.Empty).Select(i => i.EstimatedSize).Sum();
    private string DomainName => _domainName ??= FormatDomainName(Labels);

    public static DomainLabels Empty { get; } = new DomainLabels(ImmutableArray<DomainLabel>.Empty);

    private static string FormatDomainName(ImmutableArray<DomainLabel> labels)
        => string.Join(".", labels);

    public override string ToString()
        => DomainName;
}