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
    // Not cached: `with` copies private fields and would keep a stale size
    // after answers are appended (CNAME chase) or dropped (UDP truncation).
    public int EstimatedSize =>
        Answers.Sum(static i => i.EstimatedSize) +
        Authorities.Sum(static i => i.EstimatedSize) +
        Additional.Sum(static i => i.EstimatedSize);
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