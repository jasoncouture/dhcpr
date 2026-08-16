using Orleans.Concurrency;

namespace Dhcpr.Server.Orleans.LiveQueries;

public interface ILiveQueryHubGrain : IGrainWithGuidKey
{
    Task Subscribe(ILiveQueryObserver observer, CancellationToken cancellationToken = default);

    Task Unsubscribe(ILiveQueryObserver observer, CancellationToken cancellationToken = default);

    // No CancellationToken on OneWay — see ILiveQueryPublishWorker.
    [OneWay]
    Task Publish(DnsQueryEventMessage evt);
}
