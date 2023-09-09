using System.Collections.Immutable;

namespace Dhcpr.Dns.Core.Protocol;

public record DomainMessage(DomainMessageFlags Flags, ImmutableArray<DomainQuestion> Questions,
    DomainResourceRecords Records) : ISelfComputeSize
{
    private int? _size;

    // The additional 4 ushorts are the counts for questions and answers.
    public int Size => _size ??= Flags.Size + Records.Size + Questions.Select(i => i.Size).DefaultIfEmpty(0).Sum() +
                                 (sizeof(ushort) * 4);
}