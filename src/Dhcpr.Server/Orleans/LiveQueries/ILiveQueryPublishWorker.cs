using Orleans.Concurrency;

namespace Dhcpr.Server.Orleans.LiveQueries;

public interface ILiveQueryPublishWorker : IGrainWithIntegerKey
{
    /// <summary>
    /// Forwards <paramref name="evt"/> to the live-query hub. One-way; does not wait for observer delivery.
    /// </summary>
    [OneWay]
    Task PublishAsync(DnsQueryEventMessage evt, CancellationToken cancellationToken);
}
