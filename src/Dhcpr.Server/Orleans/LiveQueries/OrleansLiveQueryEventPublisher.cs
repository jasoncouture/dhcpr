using Dhcpr.Dns.Core.Protocol.Processing;

namespace Dhcpr.Server.Orleans.LiveQueries;

public sealed class OrleansLiveQueryEventPublisher : ILiveQueryEventPublisher
{
    private readonly IGrainFactory _grainFactory;

    public OrleansLiveQueryEventPublisher(IGrainFactory grainFactory)
    {
        _grainFactory = grainFactory;
    }

    public async ValueTask PublishAsync(DnsQueryEvent evt, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var worker = _grainFactory.GetGrain<ILiveQueryPublishWorker>(0);
        // OneWay: await only waits until the message is queued locally.
        // Pass None into the grain — Orleans cancels a OneWay call's CT when enqueue completes,
        // which would abort hub/observer fan-out if the request token were used.
        await worker.PublishAsync(DnsQueryEventMessage.From(evt), CancellationToken.None)
            .WaitAsync(cancellationToken);
    }
}
