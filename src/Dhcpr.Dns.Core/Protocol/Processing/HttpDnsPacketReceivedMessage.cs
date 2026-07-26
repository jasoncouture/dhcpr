namespace Dhcpr.Dns.Core.Protocol.Processing;

/// <summary>
/// Client-facing DNS-over-HTTP query: same middleware pipeline as UDP/TCP, response via TCS.
/// </summary>
public sealed record HttpDnsPacketReceivedMessage(
    DomainMessageContext Context,
    TaskCompletionSource<DomainMessage?> TaskCompletionSource)
    : DnsPacketReceivedMessage(Context), IAwaitableDnsRequest
{
    public HttpDnsPacketReceivedMessage(DomainMessageContext context)
        : this(context, new TaskCompletionSource<DomainMessage?>())
    {
    }

    protected override void Dispose(bool disposing)
    {
        TaskCompletionSource.TrySetResult(null);
    }
}
