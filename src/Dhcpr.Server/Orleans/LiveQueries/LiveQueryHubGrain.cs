using Orleans.Utilities;

namespace Dhcpr.Server.Orleans.LiveQueries;

[KeepAlive]
public sealed class LiveQueryHubGrain : Grain, ILiveQueryHubGrain
{
    private static readonly TimeSpan _observerExpiration = TimeSpan.FromMinutes(5);

    private readonly ObserverManager<ILiveQueryObserver> _observers;

    public LiveQueryHubGrain(ILogger<LiveQueryHubGrain> logger)
    {
        _observers = new ObserverManager<ILiveQueryObserver>(_observerExpiration, logger);
    }

    public async Task SubscribeAsync(ILiveQueryObserver observer, CancellationToken cancellationToken)
    {
        await Task.Yield();
        cancellationToken.ThrowIfCancellationRequested();
        _observers.Subscribe(observer, observer);
    }

    public async Task UnsubscribeAsync(ILiveQueryObserver observer, CancellationToken cancellationToken)
    {
        await Task.Yield();
        cancellationToken.ThrowIfCancellationRequested();
        _observers.Unsubscribe(observer);
    }

    public async Task PublishAsync(DnsQueryEventMessage evt, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        // OneWay OnEventAsync: await completes when each observer invoke is queued locally.
        await _observers.Notify(observer => observer.OnEventAsync(evt, CancellationToken.None));
    }
}
