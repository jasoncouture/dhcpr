using System.Collections;
using System.Collections.Immutable;

namespace Dhcpr.Dns.Core.Protocol;

public record DomainResourceRecords
(
    ImmutableArray<DomainResourceRecord> Answers,
    ImmutableArray<DomainResourceRecord> Authorities,
    ImmutableArray<DomainResourceRecord> Additional
) : IEnumerable<DomainResourceRecord>, ISelfComputeSize
{
    private int? _size;
    public int Size => _size ??= this.Select(i => i.Size).DefaultIfEmpty(0).Sum();

    public IEnumerator<DomainResourceRecord> GetEnumerator() =>
        Answers.Concat(Authorities)
            .Concat(Additional)
            .GetEnumerator();

    IEnumerator IEnumerable.GetEnumerator()
    {
        return GetEnumerator();
    }
}