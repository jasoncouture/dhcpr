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
    private readonly HashSet<string> _elements = [];

    public DataProtectionKeyGrain(ILogger<DataProtectionKeyGrain> logger)
    {
        _observers = new ObserverManager<IDataProtectionKeyObserver>(_observerExpiration, logger);
    }

    public override async Task OnActivateAsync(CancellationToken cancellationToken)
    {
        await Task.Yield();
        Merge(DataProtectionKeySnapshot.Copy());
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

    public async Task<IEnumerable<string>> GetAllAsync()
    {
        await Task.Yield();
        return _elements;
    }

    public async Task StoreAsync(string elementXml, string? friendlyName)
    {
        await Task.Yield();
        ArgumentException.ThrowIfNullOrWhiteSpace(elementXml);
        _elements.Add(elementXml);
        await PublishAsync();
    }

    private async Task PublishAsync()
    {
        await _observers.Notify(observer => observer.OnKeysAsync(_elements, CancellationToken.None));
    }

    private string[] PersistLocal()
    {
        DataProtectionKeySnapshot.Replace(_elements);
        return [.. _elements];
    }

    private void Merge(IEnumerable<string>? knownKeys)
    {
        knownKeys ??= [];
        foreach (var xml in knownKeys.Where(i => !string.IsNullOrWhiteSpace(i)))
        {
            _elements.Add(xml);
        }
    }
}
