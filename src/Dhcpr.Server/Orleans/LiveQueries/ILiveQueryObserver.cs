using Orleans.Concurrency;

namespace Dhcpr.Server.Orleans.LiveQueries;

public interface ILiveQueryObserver : IGrainObserver
{
    [OneWay]
    Task OnEventAsync(DnsQueryEventMessage evt, CancellationToken cancellationToken);
}
