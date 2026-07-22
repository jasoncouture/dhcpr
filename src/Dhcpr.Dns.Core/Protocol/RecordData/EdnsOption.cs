using System.Collections.Immutable;
using Dhcpr.Dns.Core.Protocol.Parser;

namespace Dhcpr.Dns.Core.Protocol.RecordData;

public sealed record EdnsOption(ushort Code, ImmutableArray<byte> Data)
{
    private int? _size;
    public int EstimatedSize => _size ??= sizeof(ushort) + sizeof(ushort) + Data.Length;

    public void WriteTo(ref DnsParsingSpan span)
    {
        DomainMessageEncoder.EncodeAndAdvance(ref span, Code);
        DomainMessageEncoder.EncodeAndAdvance(ref span, (ushort)Data.Length);
        Data.CopyTo(span);
        span = span[Data.Length..];
    }
}
