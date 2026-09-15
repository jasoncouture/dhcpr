using System.Collections.Immutable;
using System.Diagnostics;
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
    /// Shared across a client query and internal re-entries. Zone-cut NS
    /// addresses learned on directed hops (which bypass the response cache).
    /// </summary>
    public NameserverTipCache? NameserverTips { get; init; }

    /// <summary>
    /// Set by the cache decorator when the response was served from cache.
    /// Stored on the context so the flag is visible to outer middleware after await
    /// (AsyncLocal does not flow mutations back to the caller).
    /// </summary>
    public bool CacheHit { get; set; }

    /// <summary>
    /// DNSSEC status associated with a cache hit (Unchecked when miss or legacy entry).
    /// </summary>
    public DnssecValidationStatus CachedDnssecStatus { get; set; }

    /// <summary>
    /// When true, the cache decorator must not store the response
    /// (e.g. answers from authoritative zone files).
    /// </summary>
    public bool DoNotCacheResponse { get; set; }

    /// <summary>
    /// When true, skip both cache lookup and store (e.g. health-check probes).
    /// </summary>
    public bool BypassCache { get; init; }

    /// <summary>
    /// Address-type prefetch hop. Must not schedule another A/AAAA prefetch
    /// (A → AAAA → A would loop).
    /// </summary>
    public bool SuppressAddressPrefetch { get; init; }

    /// <summary>
    /// Human-readable reason when the pipeline is about to return SERVFAIL.
    /// Surfaced by query logging at Error level.
    /// </summary>
    public string? ServFailReason { get; set; }

    /// <summary>
    /// When a short-circuit middleware answers (blackhole, unsupported QTYPE), the
    /// live-query UI uses this label instead of the inner CoR leaf name.
    /// </summary>
    public string? AnsweredBy { get; set; }

    /// <summary>
    /// Parent span captured before the query is queued. Internal hops and DoH
    /// inherit the inbound activity across the worker queue.
    /// </summary>
    public ActivityContext ParentTraceContext { get; init; }

    /// <summary>
    /// UDP, TCP, DoT, or DoH for the originating client query.
    /// </summary>
    public DnsQuerySource Source { get; init; }

    /// <summary>
    /// RFC 7873 client cookie from the originating query, or <see langword="null"/>
    /// when the client did not send one. Copied onto internal hops so CNAME/cache
    /// chains do not walk OPT again. Null means do not write a COOKIE on the reply.
    /// </summary>
    public ImmutableArray<byte>? ClientCookie { get; set; }
}
