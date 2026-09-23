using System.Collections.Immutable;
using System.Net;

namespace Dhcpr.Dns.Core.Protocol.Processing;

public interface IInternalDomainClient : IDomainClient
{
    /// <summary>
    /// Re-enter the middleware pipeline, preserving the parent request's client/server endpoints.
    /// When <paramref name="upstreamEndpoints"/> is non-empty,
    /// <see cref="UpstreamQueryMiddleware"/> performs a directed query to those nameservers.
    /// </summary>
    ValueTask<DomainMessage> SendAsync(
        DomainMessageContext parentContext,
        DomainMessage message,
        ImmutableArray<IPEndPoint> upstreamEndpoints,
        CancellationToken cancellationToken);

    /// <summary>
    /// Re-enter the middleware pipeline for a normal (non-directed) query,
    /// preserving the parent request's client/server endpoints.
    /// </summary>
    ValueTask<DomainMessage> SendAsync(
        DomainMessageContext parentContext,
        DomainMessage message,
        CancellationToken cancellationToken);

    /// <summary>
    /// Re-enter the pipeline to fill the A/AAAA sibling cache. Own DNSSEC
    /// scope and work budget. Sets <see cref="DomainMessageContext.SuppressAddressPrefetch"/>.
    /// </summary>
    ValueTask<DomainMessage> SendPrefetchAsync(
        DomainMessageContext parentContext,
        DomainMessage message,
        CancellationToken cancellationToken);

    /// <summary>
    /// Re-enter the pipeline to replace a soon-to-expire cache entry. Bypasses
    /// the response cache so the origin is queried again. Own DNSSEC scope and
    /// work budget. Caller stores the message and the scope's validation status.
    /// </summary>
    ValueTask<DomainRefreshResult> SendRefreshAsync(
        DomainMessageContext parentContext,
        DomainMessage message,
        CancellationToken cancellationToken);
}

/// <summary>
/// Fresh answer from <see cref="IInternalDomainClient.SendRefreshAsync"/> plus the
/// DNSSEC status of that refresh, so the cache does not store it as Unchecked.
/// </summary>
public readonly record struct DomainRefreshResult(DomainMessage Message, DnssecValidationStatus SecurityStatus);
