using System.Net;

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
    /// Bypasses the response cache so probes always hit live resolution.
    /// </summary>
    ValueTask<DomainMessage?> QueryAsync(
        DomainMessage request,
        CancellationToken cancellationToken);
}
