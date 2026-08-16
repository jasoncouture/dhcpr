namespace Dhcpr.Server.Orleans.LiveQueries;

public interface ILiveQueryObserver : IGrainObserver
{
    Task OnEvent(DnsQueryEventMessage evt, CancellationToken cancellationToken = default);
}
