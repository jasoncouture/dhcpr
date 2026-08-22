using Orleans.Concurrency;

namespace Dhcpr.Server.Orleans.Cache;

public interface IDnsCacheHubGrain : IGrainWithGuidKey
{
    Task SubscribeAsync(IDnsCacheObserver observer, CancellationToken cancellationToken);

    Task UnsubscribeAsync(IDnsCacheObserver observer, CancellationToken cancellationToken);

    /// <summary>
    /// Notifies all subscribed observers of <paramref name="evt"/>. One-way.
    /// </summary>
    [OneWay]
    Task PublishAsync(DnsCacheEventMessage evt, CancellationToken cancellationToken);
}
