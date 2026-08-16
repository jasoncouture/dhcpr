using Orleans.Concurrency;

namespace Dhcpr.Server.Orleans.LiveQueries;

public interface ILiveQueryPublishWorker : IGrainWithIntegerKey
{
    [OneWay]
    Task PublishAsync(DnsQueryEventMessage evt, CancellationToken cancellationToken);
}
