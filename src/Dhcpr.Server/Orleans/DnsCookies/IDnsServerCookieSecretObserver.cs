using Orleans.Concurrency;

namespace Dhcpr.Server.Orleans.DnsCookies;

public interface IDnsServerCookieSecretObserver : IGrainObserver
{
    /// <summary>
    /// Cluster cookie HMAC key. One-way; must complete quickly.
    /// </summary>
    [OneWay]
    Task OnSecretAsync(byte[] secret, CancellationToken cancellationToken);
}
