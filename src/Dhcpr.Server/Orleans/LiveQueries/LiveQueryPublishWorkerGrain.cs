using Orleans.Concurrency;

namespace Dhcpr.Server.Orleans.LiveQueries;

/// <summary>
/// Local [StatelessWorker] ingress: DNS can OneWay-publish concurrently here without
/// contending on the single-threaded <see cref="LiveQueryHubGrain"/> activation.
/// This worker then OneWay-forwards to the hub.
/// </summary>
[StatelessWorker]
public sealed class LiveQueryPublishWorkerGrain : Grain, ILiveQueryPublishWorker
{
    public async Task Publish(DnsQueryEventMessage evt, CancellationToken cancellationToken)
    {
        var hub = GrainFactory.GetGrain<ILiveQueryHubGrain>(Guid.Empty);
        await hub.Publish(evt, cancellationToken);
    }
}
