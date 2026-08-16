using Orleans.Concurrency;
using Orleans.Utilities;

namespace Dhcpr.Server.Orleans.LiveQueries;

[KeepAlive]
public sealed class LiveQueryHubGrain : Grain, ILiveQueryHubGrain
{
    private static readonly TimeSpan ObserverExpiration = TimeSpan.FromMinutes(5);

    private readonly ObserverManager<ILiveQueryObserver> _observers;

    public LiveQueryHubGrain(ILogger<LiveQueryHubGrain> logger)
    {
        _observers = new ObserverManager<ILiveQueryObserver>(ObserverExpiration, logger);
    }

    public Task Subscribe(ILiveQueryObserver observer, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _observers.Subscribe(observer, observer);
        return Task.CompletedTask;
    }

    public Task Unsubscribe(ILiveQueryObserver observer, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _observers.Unsubscribe(observer);
        return Task.CompletedTask;
    }

    public Task Publish(DnsQueryEventMessage evt, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _observers.Notify(observer => observer.OnEvent(evt, cancellationToken));
        return Task.CompletedTask;
    }
}
