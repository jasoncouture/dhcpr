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

    public Task SubscribeAsync(ILiveQueryObserver observer, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _observers.Subscribe(observer, observer);
        return Task.CompletedTask;
    }

    public Task UnsubscribeAsync(ILiveQueryObserver observer, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _observers.Unsubscribe(observer);
        return Task.CompletedTask;
    }

    public Task PublishAsync(DnsQueryEventMessage evt, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        // Action Notify (statement body required so this does not bind Func<Task> overload).
        // Awaiting observer Tasks serializes fan-out on this grain and wedges the silo under load.
        _observers.Notify(observer =>
        {
            _ = observer.OnEventAsync(evt, CancellationToken.None);
        });
        return Task.CompletedTask;
    }
}
