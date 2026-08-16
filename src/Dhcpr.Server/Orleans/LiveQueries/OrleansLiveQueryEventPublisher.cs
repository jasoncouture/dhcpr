using Dhcpr.Dns.Core.Protocol.Processing;

namespace Dhcpr.Server.Orleans.LiveQueries;

public sealed class OrleansLiveQueryEventPublisher(IGrainFactory grainFactory) : ILiveQueryEventPublisher
{
    public async ValueTask PublishAsync(DnsQueryEvent evt, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var worker = grainFactory.GetGrain<ILiveQueryPublishWorker>(0);
        // OneWay: await only waits until the message is queued locally.
        // Do not pass cancellationToken into the grain — Orleans cancels OneWay grain CTs on enqueue.
        await worker.Publish(DnsQueryEventMessage.From(evt)).WaitAsync(cancellationToken);
    }
}
