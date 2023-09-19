using System.Collections.Immutable;

using Dhcpr.Dns.Core.Protocol.Parser;

namespace Dhcpr.Dns.Core.Protocol.RecordData;

public sealed record BlobData(ImmutableArray<byte> Blob) : IDomainResourceRecordData
{
    public int EstimatedSize => Blob.Length;

    public void WriteTo(ref DnsParsingSpan span)
    {
        DomainMessageEncoder.EncodeAndAdvance(ref span, (ushort)Blob.Length);
        Blob.CopyTo(span);
        span = span[Blob.Length..];
    }

    public static IDomainResourceRecordData ReadFrom(ref ReadOnlyDnsParsingSpan bytes, int dataLength)
    {
        var dataSpan = bytes.CurrentSpan[..dataLength];
        bytes = bytes[dataLength..];
        return new BlobData(dataSpan.ToImmutableArray());
    }
}