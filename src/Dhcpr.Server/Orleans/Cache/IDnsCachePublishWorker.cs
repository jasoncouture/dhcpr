using Orleans.Concurrency;

namespace Dhcpr.Server.Orleans.Cache;

public interface IDnsCachePublishWorker : IGrainWithIntegerKey
{
    /// <summary>
    /// Forwards <paramref name="evt"/> to the cache hub. One-way; does not wait for observer delivery.
    /// </summary>
    [OneWay]
    Task PublishAsync(DnsCacheEventMessage evt, CancellationToken cancellationToken);
}
