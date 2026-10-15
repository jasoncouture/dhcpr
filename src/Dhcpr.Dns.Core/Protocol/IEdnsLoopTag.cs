using System.Collections.Immutable;

using Dhcpr.Dns.Core.Protocol.Processing;

namespace Dhcpr.Dns.Core.Protocol;

/// <summary>
/// Stateless mark on queries this resolver sends. The value is an HMAC of the
/// question and a timestamp, keyed with the silo-shared cookie secret, so any
/// pod can recognize a packet that came back without keeping a table.
/// Other servers ignore the unknown EDNS option (RFC 6891).
/// </summary>
public interface IEdnsLoopTag
{
    /// <summary>
    /// Computes the tag for <paramref name="context"/>'s question the first
    /// time this request needs one. Later calls keep the stored value.
    /// </summary>
    void Ensure(DomainMessageContext context);

    /// <summary>
    /// Tag to copy onto a hop that asks the parent's question. A different
    /// question (glue, CNAME) gets its own tag when that request is sent.
    /// </summary>
    ImmutableArray<byte>? Share(DomainMessageContext parent, DomainMessage message);

    /// <summary>
    /// Tag for a query that has no request context, or null when the cookie
    /// secret is not available.
    /// </summary>
    ImmutableArray<byte>? Create(DomainMessage message);

    /// <summary>
    /// True when <paramref name="message"/> carries a tag this resolver would
    /// have written for its question, and the tag is still inside the skew window.
    /// </summary>
    bool IsOurs(DomainMessage message);
}
