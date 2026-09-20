using System.Security.Cryptography;

using Orleans.Utilities;

namespace Dhcpr.Server.Orleans.DnsCookies;

/// <summary>
/// In-memory HMAC key for DNS server cookies. Shared across silos
/// while this activation lives. New activations bootstrap from this
/// silo's last pushed secret; a subscriber's known secret wins when
/// the grain is still empty.
/// </summary>
[KeepAlive]
public sealed class DnsServerCookieSecretGrain : Grain, IDnsServerCookieSecretGrain
{
    public const long Key = 0;

    private static readonly TimeSpan _observerExpiration = TimeSpan.FromMinutes(5);

    private readonly ObserverManager<IDnsServerCookieSecretObserver> _observers;
    private byte[]? _secret;

    public DnsServerCookieSecretGrain(ILogger<DnsServerCookieSecretGrain> logger)
    {
        _observers = new ObserverManager<IDnsServerCookieSecretObserver>(_observerExpiration, logger);
    }

    public override async Task OnActivateAsync(CancellationToken cancellationToken)
    {
        await Task.Yield();
        var local = DnsServerCookieSecretSnapshot.Get();
        if (local is { Length: >= 16 })
            _secret = local;
    }

    public async Task SubscribeAsync(
        IDnsServerCookieSecretObserver observer,
        byte[]? knownSecret,
        CancellationToken cancellationToken)
    {
        await Task.Yield();
        cancellationToken.ThrowIfCancellationRequested();
        if (_secret is null && knownSecret is { Length: >= 16 })
            _secret = knownSecret;

        _observers.Subscribe(observer, observer);
        if (_secret is not null)
            await PublishAsync();
    }

    public async Task UnsubscribeAsync(
        IDnsServerCookieSecretObserver observer,
        CancellationToken cancellationToken)
    {
        await Task.Yield();
        cancellationToken.ThrowIfCancellationRequested();
        _observers.Unsubscribe(observer);
    }

    public async Task<byte[]> GetOrCreateAsync()
    {
        await Task.Yield();
        _secret ??= Mint();
        return _secret;
    }

    private async Task PublishAsync()
    {
        var secret = _secret;
        if (secret is null)
            return;

        await _observers.Notify(observer => observer.OnSecretAsync(secret, CancellationToken.None));
    }

    private static byte[] Mint()
    {
        var secret = new byte[32];
        RandomNumberGenerator.Fill(secret);
        return secret;
    }
}
