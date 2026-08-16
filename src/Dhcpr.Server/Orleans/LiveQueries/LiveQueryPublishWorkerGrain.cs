using Orleans.Concurrency;

namespace Dhcpr.Server.Orleans.LiveQueries;

[StatelessWorker]
public sealed class LiveQueryPublishWorkerGrain : Grain, ILiveQueryPublishWorker
{
    public async Task PublishAsync(DnsQueryEventMessage evt, CancellationToken cancellationToken)
    {
        var hub = GrainFactory.GetGrain<ILiveQueryHubGrain>(Guid.Empty);
        // OneWay: await completes when the hub mailbox accepts the message.
        await hub.PublishAsync(evt, CancellationToken.None);
    }
}
