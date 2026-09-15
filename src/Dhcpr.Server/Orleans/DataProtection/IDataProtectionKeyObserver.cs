using Orleans.Concurrency;

namespace Dhcpr.Server.Orleans.DataProtection;

public interface IDataProtectionKeyObserver : IGrainObserver
{
    /// <summary>
    /// Full key ring. One-way; must complete quickly.
    /// </summary>
    [OneWay]
    Task OnKeysAsync(IEnumerable<string> elementXml, CancellationToken cancellationToken);
}
