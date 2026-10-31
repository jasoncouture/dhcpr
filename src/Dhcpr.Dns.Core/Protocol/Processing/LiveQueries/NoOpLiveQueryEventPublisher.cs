namespace Dhcpr.Dns.Core.Protocol.Processing;

/// <summary>
/// Default publisher used when the host does not register a live-query sink.
/// </summary>
public sealed class NoOpLiveQueryEventPublisher : ILiveQueryEventPublisher
{
    public async ValueTask PublishAsync(DnsQueryEvent evt, CancellationToken cancellationToken)
    {
        await Task.Yield();
    }
}
