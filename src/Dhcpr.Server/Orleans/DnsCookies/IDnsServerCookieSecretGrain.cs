namespace Dhcpr.Server.Orleans.DnsCookies;

public interface IDnsServerCookieSecretGrain : IGrainWithIntegerKey
{
    Task SubscribeAsync(
        IDnsServerCookieSecretObserver observer,
        byte[]? knownSecret,
        CancellationToken cancellationToken);

    Task UnsubscribeAsync(IDnsServerCookieSecretObserver observer, CancellationToken cancellationToken);

    Task<byte[]> GetOrCreateAsync();
}
