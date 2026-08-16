using Orleans.Concurrency;

namespace Dhcpr.Server.Orleans.LiveQueries;

[StatelessWorker]
public sealed class LiveQueryPublishWorkerGrain : Grain, ILiveQueryPublishWorker
{
    public Task PublishAsync(DnsQueryEventMessage evt, CancellationToken cancellationToken)
    {
        var hub = GrainFactory.GetGrain<ILiveQueryHubGrain>(Guid.Empty);
        // OneWay hub publish: do not await — keeps the worker turn short under flood.
        hub.PublishAsync(evt, CancellationToken.None);
        return Task.CompletedTask;
    }
}
