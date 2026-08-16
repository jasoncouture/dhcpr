using System.Collections.Immutable;

using Orleans.Concurrency;
using Orleans.Utilities;

namespace Dhcpr.Server.Orleans.LiveQueries;

[KeepAlive]
public sealed class LiveQueryHubGrain : Grain, ILiveQueryHubGrain
{
    public const int RingCapacity = 250;

    private static readonly TimeSpan ObserverExpiration = TimeSpan.FromMinutes(5);

    private readonly ObserverManager<ILiveQueryObserver> _observers;
    private readonly LinkedList<DnsQueryEventMessage> _ring = new();

    public LiveQueryHubGrain(ILogger<LiveQueryHubGrain> logger)
    {
        _observers = new ObserverManager<ILiveQueryObserver>(ObserverExpiration, logger);
    }

    public async Task Subscribe(ILiveQueryObserver observer, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _observers.Subscribe(observer, observer);

        // Replay newest-first so a silo joining mid-flight gets a snapshot.
        ImmutableArray<DnsQueryEventMessage> snapshot;
        lock (_ring)
            snapshot = _ring.ToImmutableArray();

        foreach (var evt in snapshot)
        {
            cancellationToken.ThrowIfCancellationRequested();
            await observer.OnEvent(evt, cancellationToken);
        }
    }

    public Task RefreshSubscription(ILiveQueryObserver observer, CancellationToken cancellationToken)
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

        lock (_ring)
        {
            _ring.AddFirst(evt);
            while (_ring.Count > RingCapacity)
                _ring.RemoveLast();
        }

        _observers.Notify(observer => observer.OnEvent(evt, cancellationToken));
        return Task.CompletedTask;
    }
}
