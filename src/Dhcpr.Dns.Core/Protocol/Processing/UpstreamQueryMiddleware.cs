using System.Net;

using Dhcpr.Core.Linq;
using Dhcpr.Dns.Core.Protocol;

namespace Dhcpr.Dns.Core.Protocol.Processing;

/// <summary>
/// Directed stub query to nameservers listed on <see cref="DomainMessageContext.UpstreamEndpoints"/>.
/// </summary>
public sealed class UpstreamQueryMiddleware : IDomainMessageMiddleware
{
    private const int MaxParallelNameservers = 3;

    private readonly IDomainClientFactory _clientFactory;

    public UpstreamQueryMiddleware(IDomainClientFactory clientFactory)
    {
        _clientFactory = clientFactory;
    }

    public string Name => "Upstream Query";
    public int Priority => 100;

    public async ValueTask<DomainMessage?> ProcessAsync(
        DomainMessageContext context,
        CancellationToken cancellationToken)
    {
        if (context.UpstreamEndpoints is not { Length: > 0 } endPoints)
            return null;

        using var pooled = endPoints.ToPooledList();
        var client = await _clientFactory.GetParallelDomainClient(
            SelectQueryEndpoints(pooled),
            cancellationToken);
        return await client.SendAsync(context.DomainMessage, cancellationToken);
    }

    private static IEnumerable<DomainClientOptions> SelectQueryEndpoints(PooledList<IPEndPoint> endPoints)
    {
        IEnumerable<IPEndPoint> selected = endPoints.Count <= MaxParallelNameservers
            ? endPoints
            : endPoints.OrderBy(_ => Random.Shared.Next()).Take(MaxParallelNameservers);

        return selected.Select(i => new DomainClientOptions { EndPoint = i, Type = DomainClientType.Udp })
            .ToArray();
    }
}
