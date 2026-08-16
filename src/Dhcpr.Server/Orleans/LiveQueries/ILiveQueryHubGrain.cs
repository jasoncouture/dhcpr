using Orleans.Concurrency;

namespace Dhcpr.Server.Orleans.LiveQueries;

public interface ILiveQueryHubGrain : IGrainWithGuidKey
{
    Task SubscribeAsync(ILiveQueryObserver observer, CancellationToken cancellationToken);

    Task UnsubscribeAsync(ILiveQueryObserver observer, CancellationToken cancellationToken);

    [OneWay]
    Task PublishAsync(DnsQueryEventMessage evt, CancellationToken cancellationToken);
}
