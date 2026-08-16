using System.Collections.Immutable;

namespace Dhcpr.Server.Orleans.LiveQueries;

public sealed class LiveQueryHubGrain : Grain, ILiveQueryHubGrain
{
    public const int RingCapacity = 250;

    private readonly HashSet<ILiveQueryObserver> _observers = new();
    private readonly LinkedList<DnsQueryEventMessage> _ring = new();

    public async Task Subscribe(ILiveQueryObserver observer, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _observers.Add(observer);

        // Replay newest-first so a silo joining mid-flight gets a snapshot.
        ImmutableArray<DnsQueryEventMessage> snapshot;
        lock (_ring)
            snapshot = _ring.ToImmutableArray();

        foreach (var evt in snapshot)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                await observer.OnEvent(evt, cancellationToken);
            }
            catch
            {
                _observers.Remove(observer);
                throw;
            }
        }
    }

    public Task Unsubscribe(ILiveQueryObserver observer, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _observers.Remove(observer);
        return Task.CompletedTask;
    }

    public async Task Publish(DnsQueryEventMessage evt, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        lock (_ring)
        {
            _ring.AddFirst(evt);
            while (_ring.Count > RingCapacity)
                _ring.RemoveLast();
        }

        List<ILiveQueryObserver>? dead = null;
        foreach (var observer in _observers)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                await observer.OnEvent(evt, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch
            {
                dead ??= new List<ILiveQueryObserver>();
                dead.Add(observer);
            }
        }

        if (dead is null)
            return;

        foreach (var observer in dead)
            _observers.Remove(observer);
    }
}
