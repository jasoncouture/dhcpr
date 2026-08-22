using Orleans.Concurrency;

namespace Dhcpr.Server.Orleans.Cache;

public interface IDnsCacheObserver : IGrainObserver
{
    /// <summary>
    /// Receives one cache-replication event. One-way; must complete quickly.
    /// </summary>
    [OneWay]
    Task OnEventAsync(DnsCacheEventMessage evt, CancellationToken cancellationToken);
}
