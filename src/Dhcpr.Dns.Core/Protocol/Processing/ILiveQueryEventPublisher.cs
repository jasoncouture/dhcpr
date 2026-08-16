namespace Dhcpr.Dns.Core.Protocol.Processing;

/// <summary>
/// Publishes live query UI events. Implementations must complete quickly (e.g. Orleans OneWay
/// local enqueue) so DNS middleware is not blocked on cluster fan-out.
/// </summary>
public interface ILiveQueryEventPublisher
{
    ValueTask PublishAsync(DnsQueryEvent evt, CancellationToken cancellationToken = default);
}
