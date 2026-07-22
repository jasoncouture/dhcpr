using System.Collections.Immutable;
using Dhcpr.Dns.Core.Protocol.Parser;

namespace Dhcpr.Dns.Core.Protocol.RecordData;

public sealed record OptionData(ImmutableArray<EdnsOption> Options) : IDomainResourceRecordData
{
    private int? _size;
    public int EstimatedSize => _size ??= 2 + Options.Sum(o => o.EstimatedSize);

    public void WriteTo(ref DnsParsingSpan span)
    {
        var totalDataSize = EstimatedSize - 2;
        DomainMessageEncoder.EncodeAndAdvance(ref span, (ushort)totalDataSize);
        foreach (var opt in Options)
        {
            opt.WriteTo(ref span);
        }
    }

    public static IDomainResourceRecordData ReadFrom(ref ReadOnlyDnsParsingSpan bytes, int dataLength)
    {
        var endOffset = bytes.Offset + dataLength;
        var options = ImmutableArray.CreateBuilder<EdnsOption>();
        while (bytes.Offset < endOffset)
        {
            var code = DomainMessageEncoder.ReadUnsignedShortAndAdvance(ref bytes);
            var len = DomainMessageEncoder.ReadUnsignedShortAndAdvance(ref bytes);
            var dataSpan = bytes.CurrentSpan[..len];
            bytes = bytes[len..];
            options.Add(new EdnsOption(code, dataSpan.ToImmutableArray()));
        }
        return new OptionData(options.ToImmutable());
    }
}
