using System.Collections.Immutable;
using System.Net;

namespace Dhcpr.Dns.Core.Protocol.Processing;

public record DomainMessageContext(IPEndPoint? ClientEndPoint, IPEndPoint? ServerEndPoint, DomainMessage DomainMessage)
{
    public bool Cancel { get; set; }

    /// <summary>
    /// When set, <see cref="UpstreamQueryMiddleware"/> queries these nameservers directly
    /// instead of running forward/recursive resolution.
    /// </summary>
    public ImmutableArray<IPEndPoint>? UpstreamEndpoints { get; init; }

    /// <summary>
    /// True when this context was created by an internal pipeline re-entry.
    /// Client/server endpoints are preserved from the originating request for logging.
    /// </summary>
    public bool IsInternal { get; init; }
}
