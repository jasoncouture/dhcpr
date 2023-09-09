using System.Collections.Immutable;

namespace Dhcpr.Dns.Core.Protocol;

public sealed record BlobData(ImmutableArray<byte> Blob) : IDomainResourceRecordData
{
    public int Size => Blob.Length;

    public void WriteTo(ref Span<byte> span)
    {
        Blob.CopyTo(span);
        span = span[Blob.Length..];
    }

    public static IDomainResourceRecordData ReadFrom(ReadOnlySpan<byte> bytes)
    {
        return new BlobData(bytes.ToImmutableArray());
    }
}