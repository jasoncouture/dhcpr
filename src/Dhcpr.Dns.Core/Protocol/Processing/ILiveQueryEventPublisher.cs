namespace Dhcpr.Dns.Core.Protocol.Processing;

public interface ILiveQueryEventPublisher
{
    /// <summary>
    /// Enqueues a live-query event for UI fan-out. Must complete quickly (local OneWay enqueue);
    /// must not await cluster observer delivery.
    /// </summary>
    ValueTask PublishAsync(DnsQueryEvent evt, CancellationToken cancellationToken);
}
