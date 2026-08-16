using Dhcpr.Dns.Core.Protocol.Processing;

namespace Dhcpr.Server.Orleans.LiveQueries;

public sealed class OrleansLiveQueryEventPublisher(IGrainFactory grainFactory) : ILiveQueryEventPublisher
{
    public async ValueTask PublishAsync(DnsQueryEvent evt, CancellationToken cancellationToken = default)
    {
        var worker = grainFactory.GetGrain<ILiveQueryPublishWorker>(0);
        // OneWay: await only waits until the message is queued on a local StatelessWorker.
        await worker.Publish(DnsQueryEventMessage.From(evt), cancellationToken);
    }
}
