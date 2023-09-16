namespace Dhcpr.Dns.Core.Protocol;

public record struct DomainLabel(string Label) : ISelfComputeEstimatedSize
{
    private int? _size;
    public int EstimatedSize => _size ??= 1 + Label.Length;
    public override string ToString() => Label;

    public static DomainLabel Empty { get; } = new(string.Empty);
}