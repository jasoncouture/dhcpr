namespace Dhcpr.Dns.Core.Protocol.Processing;

public readonly record struct DnsQueryExecutionResult(
    DnsQueryExecutionStatus Status,
    byte[]? ResponseWire)
{
    public static DnsQueryExecutionResult Ok(byte[] wire)
        => new(DnsQueryExecutionStatus.Success, wire);

    public static DnsQueryExecutionResult Fail(DnsQueryExecutionStatus status)
        => new(status, null);
}
