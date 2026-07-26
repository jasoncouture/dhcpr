namespace Dhcpr.Dns.Core.Protocol.Processing;

/// <summary>
/// A queued DNS request that expects its response via <see cref="TaskCompletionSource"/>
/// instead of a socket write (internal recursion hops and HTTP/DoH).
/// </summary>
public interface IAwaitableDnsRequest
{
    TaskCompletionSource<DomainMessage?> TaskCompletionSource { get; }
}
