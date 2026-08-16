using Dhcpr.Dns.Core.Protocol.Processing;

namespace Dhcpr.Server.Orleans.LiveQueries;

public sealed class OrleansLiveQueryEventPublisher(IGrainFactory grainFactory) : ILiveQueryEventPublisher
{
    public async ValueTask PublishAsync(DnsQueryEvent evt, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var worker = grainFactory.GetGrain<ILiveQueryPublishWorker>(0);
        // OneWay: await only waits until the message is queued locally.
        // Pass None into the grain — Orleans cancels a OneWay call's CT when enqueue completes,
        // which would abort hub/observer fan-out if the request token were used.
        await worker.Publish(DnsQueryEventMessage.From(evt), CancellationToken.None)
            .WaitAsync(cancellationToken);
    }
}
