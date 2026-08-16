using Orleans.Concurrency;

namespace Dhcpr.Server.Orleans.LiveQueries;

/// <summary>
/// Local-only entry point: DNS middleware OneWay-invokes this worker,
/// which then publishes to the cluster-wide hub grain.
/// </summary>
[StatelessWorker]
public sealed class LiveQueryPublishWorkerGrain : Grain, ILiveQueryPublishWorker
{
    public Task Publish(DnsQueryEventMessage evt, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var hub = GrainFactory.GetGrain<ILiveQueryHubGrain>(Guid.Empty);
        // OneWay on the hub: await only waits until the message is queued.
        return hub.Publish(evt, cancellationToken);
    }
}
