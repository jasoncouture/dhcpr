using Orleans.Concurrency;

namespace Dhcpr.Server.Orleans.LiveQueries;

[StatelessWorker]
public sealed class LiveQueryPublishWorkerGrain : Grain, ILiveQueryPublishWorker
{
    public async Task PublishAsync(DnsQueryEventMessage evt, CancellationToken cancellationToken)
    {
        var hub = GrainFactory.GetGrain<ILiveQueryHubGrain>(Guid.Empty);
        await hub.PublishAsync(evt, cancellationToken);
    }
}
