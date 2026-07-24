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

    /// <summary>
    /// Depth of internal pipeline re-entry. Client requests are 0; each
    /// <see cref="IInternalDomainClient"/> hop increments by one.
    /// </summary>
    public int InternalHopDepth { get; init; }

    /// <summary>
    /// DNSSEC validation tracking for the lifetime of a query and its internal hops.
    /// </summary>
    public DnssecScope? DnssecScope { get; init; }

    /// <summary>
    /// Shared across a client query and all internal re-entries. Caps fan-out
    /// from glue / parallel NS lookups that hop-depth alone cannot stop.
    /// </summary>
    public QueryWorkBudget? WorkBudget { get; init; }

    /// <summary>
    /// Set by the cache decorator when the response was served from cache.
    /// Stored on the context so the flag is visible to outer middleware after await
    /// (AsyncLocal does not flow mutations back to the caller).
    /// </summary>
    public bool CacheHit { get; set; }
}
