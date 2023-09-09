namespace Dhcpr.Dns.Core.Protocol;

public interface IDomainResourceRecordData : ISelfComputeSize
{
    void WriteTo(ref Span<byte> span);
    static abstract IDomainResourceRecordData ReadFrom(ReadOnlySpan<byte> bytes);
}