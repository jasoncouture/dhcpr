using System.Collections;
using System.Collections.Immutable;

namespace Dhcpr.Dns.Core.Protocol;

public record DomainResourceRecords
(
    ImmutableArray<DomainResourceRecord> Answers,
    ImmutableArray<DomainResourceRecord> Authorities,
    ImmutableArray<DomainResourceRecord> Additional
) : IEnumerable<DomainResourceRecord>, ISelfComputeEstimatedSize
{
    private int? _size;
    public int EstimatedSize => _size ??= this.Select(i => i.EstimatedSize).DefaultIfEmpty(0).Sum();
    public static DomainResourceRecords Empty { get; } = new();

    private DomainResourceRecords() : this(ImmutableArray<DomainResourceRecord>.Empty,
        ImmutableArray<DomainResourceRecord>.Empty, ImmutableArray<DomainResourceRecord>.Empty)
    {
        
    }
    public IEnumerator<DomainResourceRecord> GetEnumerator() =>
        Answers.Concat(Authorities)
            .Concat(Additional)
            .GetEnumerator();

    IEnumerator IEnumerable.GetEnumerator()
    {
        return GetEnumerator();
    }
}