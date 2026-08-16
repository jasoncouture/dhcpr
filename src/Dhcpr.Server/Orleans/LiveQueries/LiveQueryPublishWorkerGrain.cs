using Orleans.Concurrency;

namespace Dhcpr.Server.Orleans.LiveQueries;

[StatelessWorker]
public sealed class LiveQueryPublishWorkerGrain : Grain, ILiveQueryPublishWorker
{
    public async Task Publish(DnsQueryEventMessage evt, CancellationToken cancellationToken)
    {
        var hub = GrainFactory.GetGrain<ILiveQueryHubGrain>(Guid.Empty);
        await hub.Publish(evt, cancellationToken);
    }
}
