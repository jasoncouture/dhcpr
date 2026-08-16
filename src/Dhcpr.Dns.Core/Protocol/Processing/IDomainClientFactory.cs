namespace Dhcpr.Dns.Core.Protocol.Processing;

public interface IDomainClientFactory
{
    public ValueTask<IDomainClient> GetParallelDomainClientAsync(IEnumerable<DomainClientOptions> options,
        CancellationToken cancellationToken);

    public ValueTask<IDomainClient> GetDomainClientAsync(DomainClientOptions options,
        CancellationToken cancellationToken);
}