using Orleans.Concurrency;

namespace Dhcpr.Server.Orleans.LiveQueries;

/// <summary>
/// Local-only entry point: DNS middleware OneWay-invokes this worker,
/// which then publishes to the cluster-wide hub grain.
/// </summary>
[StatelessWorker]
public sealed class LiveQueryPublishWorkerGrain : Grain, ILiveQueryPublishWorker
{
    public Task Publish(DnsQueryEventMessage evt)
    {
        var hub = GrainFactory.GetGrain<ILiveQueryHubGrain>(Guid.Empty);
        return hub.Publish(evt);
    }
}
