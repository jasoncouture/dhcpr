using System.Collections.Immutable;

using Dhcpr.Dns.Core.Protocol.Parser;

namespace Dhcpr.Dns.Core.Protocol.RecordData;

public sealed record BlobData(ImmutableArray<byte> Blob) : IDomainResourceRecordData
{
    public int EstimatedSize => Blob.Length;

    public void WriteTo(ref DnsParsingSpan span)
    {
        Blob.CopyTo(span);
        span = span[Blob.Length..];
    }

    public static IDomainResourceRecordData ReadFrom(ReadOnlyDnsParsingSpan bytes)
    {
        return new BlobData(bytes.CurrentSpan.ToImmutableArray());
    }
}