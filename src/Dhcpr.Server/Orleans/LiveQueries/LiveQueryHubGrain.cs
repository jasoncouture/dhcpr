using Orleans.Concurrency;
using Orleans.Utilities;

namespace Dhcpr.Server.Orleans.LiveQueries;

/// <summary>
/// Singleton fan-out grain. Activations are single-threaded; high-rate DNS publish
/// ingress is absorbed by <see cref="LiveQueryPublishWorkerGrain"/> ([StatelessWorker])
/// so callers only queue work here instead of blocking on this grain's turn.
/// </summary>
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

    public async Task Publish(DnsQueryEventMessage evt, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        // Observers are OneWay — Notify awaits enqueue only, on this grain's turn.
        await _observers.Notify(observer => observer.OnEvent(evt, cancellationToken));
    }
}
