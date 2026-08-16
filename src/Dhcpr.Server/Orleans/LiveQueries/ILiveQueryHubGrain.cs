using Orleans.Concurrency;

namespace Dhcpr.Server.Orleans.LiveQueries;

public interface ILiveQueryHubGrain : IGrainWithGuidKey
{
    Task Subscribe(ILiveQueryObserver observer, CancellationToken cancellationToken = default);

    Task Unsubscribe(ILiveQueryObserver observer, CancellationToken cancellationToken = default);

    [OneWay]
    Task Publish(DnsQueryEventMessage evt, CancellationToken cancellationToken = default);
}
