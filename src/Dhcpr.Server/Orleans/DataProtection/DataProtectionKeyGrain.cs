using Orleans.Utilities;

namespace Dhcpr.Server.Orleans.DataProtection;

/// <summary>
/// In-memory key ring for ASP.NET Data Protection. Shared across silos
/// while this activation lives. New activations bootstrap from this
/// silo's last pushed ring.
/// </summary>
[KeepAlive]
public sealed class DataProtectionKeyGrain : Grain, IDataProtectionKeyGrain
{
    public const long Key = 0;

    private static readonly TimeSpan _observerExpiration = TimeSpan.FromMinutes(5);

    private readonly ObserverManager<IDataProtectionKeyObserver> _observers;
    private readonly List<string> _elements = [];

    public DataProtectionKeyGrain(ILogger<DataProtectionKeyGrain> logger)
    {
        _observers = new ObserverManager<IDataProtectionKeyObserver>(_observerExpiration, logger);
    }

    public override Task OnActivateAsync(CancellationToken cancellationToken)
    {
        Merge(DataProtectionKeySnapshot.Copy());
        return Task.CompletedTask;
    }

    public async Task SubscribeAsync(
        IDataProtectionKeyObserver observer,
        IReadOnlyList<string> knownKeys,
        CancellationToken cancellationToken)
    {
        await Task.Yield();
        cancellationToken.ThrowIfCancellationRequested();
        Merge(knownKeys);
        _observers.Subscribe(observer, observer);
        await PublishAsync();
    }

    public async Task UnsubscribeAsync(
        IDataProtectionKeyObserver observer,
        CancellationToken cancellationToken)
    {
        await Task.Yield();
        cancellationToken.ThrowIfCancellationRequested();
        _observers.Unsubscribe(observer);
    }

    public async Task<IReadOnlyList<string>> GetAllAsync()
    {
        await Task.Yield();
        return PersistLocal();
    }

    public async Task StoreAsync(string elementXml, string? friendlyName)
    {
        await Task.Yield();
        ArgumentException.ThrowIfNullOrWhiteSpace(elementXml);
        if (_elements.Contains(elementXml))
            return;
        _elements.Add(elementXml);
        await PublishAsync();
    }

    private async Task PublishAsync()
    {
        var copy = PersistLocal();
        await _observers.Notify(observer => observer.OnKeysAsync(copy, CancellationToken.None));
    }

    private string[] PersistLocal()
    {
        var copy = _elements.ToArray();
        DataProtectionKeySnapshot.Replace(copy);
        return copy;
    }

    private void Merge(IReadOnlyList<string>? knownKeys)
    {
        if (knownKeys is null || knownKeys.Count == 0)
            return;
        foreach (var xml in knownKeys)
        {
            if (string.IsNullOrWhiteSpace(xml) || _elements.Contains(xml))
                continue;
            _elements.Add(xml);
        }
    }
}
