using Orleans.Concurrency;

namespace Dhcpr.Server.Orleans.LiveQueries;

public interface ILiveQueryPublishWorker : IGrainWithIntegerKey
{
    [OneWay]
    Task Publish(DnsQueryEventMessage evt, CancellationToken cancellationToken = default);
}
