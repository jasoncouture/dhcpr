namespace Dhcpr.Dns.Core.Protocol.Processing;

public interface IDomainClientFactory
{
    /// <summary>
    /// Builds a client that races the given <paramref name="options"/> and returns the first successful answer.
    /// </summary>
    public ValueTask<IDomainClient> GetParallelDomainClientAsync(IEnumerable<DomainClientOptions> options,
        CancellationToken cancellationToken);

    /// <summary>
    /// Builds a client for a single <paramref name="options"/> (internal, UDP with TCP truncation fallback, and/or TCP).
    /// </summary>
    public ValueTask<IDomainClient> GetDomainClientAsync(DomainClientOptions options,
        CancellationToken cancellationToken);
}