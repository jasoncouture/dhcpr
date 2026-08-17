using Orleans.Concurrency;

namespace Dhcpr.Server.Orleans.LiveQueries;

public interface ILiveQueryObserver : IGrainObserver
{
    /// <summary>
    /// Receives one live-query event. One-way; must complete quickly.
    /// </summary>
    [OneWay]
    Task OnEventAsync(DnsQueryEventMessage evt, CancellationToken cancellationToken);
}
