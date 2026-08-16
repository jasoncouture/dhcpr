using Orleans.Concurrency;

namespace Dhcpr.Server.Orleans.LiveQueries;

public interface ILiveQueryObserver : IGrainObserver
{
    [OneWay]
    Task OnEvent(DnsQueryEventMessage evt, CancellationToken cancellationToken);
}
