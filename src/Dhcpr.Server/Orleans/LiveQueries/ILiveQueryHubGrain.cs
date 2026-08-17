using Orleans.Concurrency;

namespace Dhcpr.Server.Orleans.LiveQueries;

public interface ILiveQueryHubGrain : IGrainWithGuidKey
{
    /// <summary>
    /// Registers <paramref name="observer"/> for query-event fan-out.
    /// </summary>
    Task SubscribeAsync(ILiveQueryObserver observer, CancellationToken cancellationToken);

    /// <summary>
    /// Unregisters <paramref name="observer"/>.
    /// </summary>
    Task UnsubscribeAsync(ILiveQueryObserver observer, CancellationToken cancellationToken);

    /// <summary>
    /// Notifies all subscribed observers of <paramref name="evt"/>. One-way.
    /// </summary>
    [OneWay]
    Task PublishAsync(DnsQueryEventMessage evt, CancellationToken cancellationToken);
}
