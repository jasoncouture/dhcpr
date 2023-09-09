namespace Dhcpr.Dns.Core.Protocol;

public record DomainLabel(string Label) : ISelfComputeSize
{
    private int? _size;
    public int Size => _size ??= 1 + Label.Length;
    public override string ToString() => Label;

    public static DomainLabel Empty { get; } = new(string.Empty);
}