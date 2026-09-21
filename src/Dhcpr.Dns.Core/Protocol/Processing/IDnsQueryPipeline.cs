namespace Dhcpr.Dns.Core.Protocol.Processing;

/// <summary>
/// Runs the resolve onion in a new DI scope. Does not write to a socket.
/// </summary>
public interface IDnsQueryPipeline
{
    ValueTask<DomainMessage?> ExecuteAsync(
        DomainMessageContext context,
        CancellationToken cancellationToken);
}
