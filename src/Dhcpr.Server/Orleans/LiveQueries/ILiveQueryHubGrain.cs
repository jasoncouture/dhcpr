using Orleans.Concurrency;

namespace Dhcpr.Server.Orleans.LiveQueries;

public interface ILiveQueryHubGrain : IGrainWithGuidKey
{
    Task Subscribe(ILiveQueryObserver observer, CancellationToken cancellationToken);

    /// <summary>
    /// Renews observer expiration without replaying the event ring.
    /// </summary>
    Task RefreshSubscription(ILiveQueryObserver observer, CancellationToken cancellationToken);

    Task Unsubscribe(ILiveQueryObserver observer, CancellationToken cancellationToken);

    [OneWay]
    Task Publish(DnsQueryEventMessage evt, CancellationToken cancellationToken);
}
