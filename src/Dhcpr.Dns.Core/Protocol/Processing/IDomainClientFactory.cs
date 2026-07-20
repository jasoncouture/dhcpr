namespace Dhcpr.Dns.Core.Protocol.Processing;

public interface IDomainClientFactory
{
    public ValueTask<IDomainClient> GetParallelDomainClient(IEnumerable<DomainClientOptions> options,
        CancellationToken cancellationToken = default);

    public ValueTask<IDomainClient> GetDomainClient(DomainClientOptions options,
        CancellationToken cancellationToken = default);
}