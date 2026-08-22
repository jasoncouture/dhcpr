using Orleans.Concurrency;

namespace Dhcpr.Server.Orleans.Cache;

[StatelessWorker]
public sealed class DnsCachePublishWorkerGrain : Grain, IDnsCachePublishWorker
{
    public async Task PublishAsync(DnsCacheEventMessage evt, CancellationToken cancellationToken)
    {
        var hub = GrainFactory.GetGrain<IDnsCacheHubGrain>(DnsCacheHubGrain.Key);
        await hub.PublishAsync(evt, CancellationToken.None);
    }
}
