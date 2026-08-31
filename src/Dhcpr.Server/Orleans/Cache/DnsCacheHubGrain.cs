using Orleans.Utilities;

namespace Dhcpr.Server.Orleans.Cache;

[KeepAlive]
public sealed class DnsCacheHubGrain : Grain, IDnsCacheHubGrain
{
    public static readonly Guid Key = Guid.Parse("cace0000-0000-4000-8000-000000000001");

    private static readonly TimeSpan _observerExpiration = TimeSpan.FromMinutes(5);

    private readonly ObserverManager<IDnsCacheObserver> _observers;

    public DnsCacheHubGrain(ILogger<DnsCacheHubGrain> logger)
    {
        _observers = new ObserverManager<IDnsCacheObserver>(_observerExpiration, logger);
    }

    public async Task SubscribeAsync(IDnsCacheObserver observer, CancellationToken cancellationToken)
    {
        await Task.Yield();
        cancellationToken.ThrowIfCancellationRequested();
        _observers.Subscribe(observer, observer);
    }

    public async Task UnsubscribeAsync(IDnsCacheObserver observer, CancellationToken cancellationToken)
    {
        await Task.Yield();
        cancellationToken.ThrowIfCancellationRequested();
        _observers.Unsubscribe(observer);
    }

    public async Task PublishAsync(DnsCacheEventMessage evt, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await _observers.Notify(observer => observer.OnEventAsync(evt, CancellationToken.None));
    }
}
