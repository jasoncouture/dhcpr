using System.Collections.Immutable;
using System.Net;

namespace Dhcpr.Dns.Core.Protocol.Processing;

public interface IInternalDomainClient : IDomainClient
{
    /// <summary>
    /// Re-enter the middleware pipeline. When <paramref name="upstreamEndpoints"/> is non-empty,
    /// <see cref="UpstreamQueryMiddleware"/> performs a directed query to those nameservers.
    /// </summary>
    ValueTask<DomainMessage> SendAsync(
        DomainMessage message,
        ImmutableArray<IPEndPoint> upstreamEndpoints,
        CancellationToken cancellationToken);
}
