using System.Collections.Concurrent;

using Dhcpr.Core.Linq;

namespace Dhcpr.Core;

public class SimpleMessenger : ISimpleMessenger
{
    public static ISimpleMessenger Default { get; } = new SimpleMessenger();
    private readonly HashSet<WeakSubscription> _subscribers = new();

    public IDisposable Subscribe(ISubscriber subscriber)
    {
        var subscription = new WeakSubscription(subscriber);
        lock (_subscribers)
            _subscribers.Add(subscription);

        return subscription;
    }

    private PooledList<WeakSubscription> GetSubscribers()
    {
        lock (_subscribers)
            return _subscribers.ToPooledList();
    }

    private void RemoveAll(IEnumerable<WeakSubscription> subscribers)
    {
        foreach (var subscriber in subscribers)
        {
            lock (_subscribers)
                _subscribers.Remove(subscriber);
        }
    }

    public async ValueTask BroadcastAsync(object sender, object data, CancellationToken cancellationToken)
    {
        using var broadcastSubscribers = GetSubscribers();
        var subscriptionsToRemove = new ConcurrentBag<WeakSubscription>();
        if (broadcastSubscribers.Count == 0) return;
        await Parallel.ForEachAsync(broadcastSubscribers, cancellationToken, async (subscription, token) =>
        {
            if (DestroyIfDead(subscription)) return;
            if (!await subscription.SendAsync(sender, data, token))
            {
                lock (_subscribers)
                    _subscribers.Remove(subscription);
            }
        });
    }

    private void RemoveSubscription(WeakSubscription subscription)
    {
        lock (_subscribers)
            _subscribers.Remove(subscription);
    }

    private bool DestroyIfDead(WeakSubscription subscription)
    {
        if (subscription.IsAlive) return false;
        RemoveSubscription(subscription);
        return true;
    }

    public async ValueTask SendTo(object receiver, object sender, object data, CancellationToken cancellationToken)
    {
        if (receiver is not ISubscriber subscriber) return;
        using var allSubscribers = GetSubscribers();
        foreach (var subscription in allSubscribers)
        {
            if (DestroyIfDead(subscription)) continue;
            if (!subscription.IsSubscriber(subscriber)) continue;
            if (!await subscription.SendAsync(sender, data, cancellationToken))
            {
                RemoveSubscription(subscription);
            }
        }
    }
}