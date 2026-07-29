using System.Net;

using Dhcpr.Dns.Core.Protocol;

namespace Dhcpr.Dns.Core.Protocol.Processing;

public interface IDnsQueryExecutor
{
    /// <summary>
    /// Decode a DNS wire message, run it through the shared resolver pipeline, and return the response wire bytes.
    /// </summary>
    ValueTask<DnsQueryExecutionResult> ExecuteAsync(
        ReadOnlyMemory<byte> requestWire,
        IPEndPoint clientEndPoint,
        IPEndPoint serverEndPoint,
        CancellationToken cancellationToken);

    /// <summary>
    /// Run a typed request through the shared resolver pipeline (used by health checks).
    /// </summary>
    ValueTask<DomainMessage?> QueryAsync(
        DomainMessage request,
        CancellationToken cancellationToken);
}

public enum DnsQueryExecutionStatus
{
    Success,
    EmptyRequest,
    RequestTooLarge,
    InvalidWireFormat,
    NoResponse,
    Cancelled
}

public readonly record struct DnsQueryExecutionResult(
    DnsQueryExecutionStatus Status,
    byte[]? ResponseWire)
{
    public static DnsQueryExecutionResult Ok(byte[] wire)
        => new(DnsQueryExecutionStatus.Success, wire);

    public static DnsQueryExecutionResult Fail(DnsQueryExecutionStatus status)
        => new(status, null);
}
