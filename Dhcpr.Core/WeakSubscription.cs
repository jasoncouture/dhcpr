using System.Diagnostics.CodeAnalysis;

namespace Dhcpr.Core;

class WeakSubscription : IDisposable
{
    private bool _dead = false;

    public WeakSubscription(ISubscriber subscriber)
    {
        _subscriberReference = new WeakReference(subscriber);
    }

    public bool IsSubscriber(ISubscriber subscriber)
    {
        if (!TryGetSubscriber(out var otherSubscriber)) return false;
        if (!ReferenceEquals(subscriber, otherSubscriber)) return false;
        return true;
    }

    public bool IsAlive => TryGetSubscriber(out _);

    private bool TryGetSubscriber([NotNullWhen(true)] out ISubscriber? subscriber)
    {
        subscriber = null;
        if (_dead) return false;
        if (!_subscriberReference.IsAlive)
            return false;
        subscriber = _subscriberReference.Target as ISubscriber;

        if (subscriber is null) return false;
        return true;
    }

    public void Dispose()
    {
        _dead = true;
    }

    private readonly WeakReference _subscriberReference = new(new object());

    public async ValueTask<bool> SendAsync(object sender, object data, CancellationToken cancellationToken)
    {
        if (!TryGetSubscriber(out var subscriber)) return false;
        await subscriber.OnMessageAsync(sender, data, cancellationToken);
        return true;
    }
}