using Orleans.Concurrency;

namespace Dhcpr.Server.Orleans.LiveQueries;

public interface ILiveQueryPublishWorker : IGrainWithIntegerKey
{
    // No CancellationToken: Orleans cancels the grain CT when a OneWay call "completes"
    // (message queued), which would abort Publish before the hub runs.
    [OneWay]
    Task Publish(DnsQueryEventMessage evt);
}
