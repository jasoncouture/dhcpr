namespace Dhcpr.Server.Orleans.DataProtection;

public interface IDataProtectionKeyGrain : IGrainWithIntegerKey
{
    Task SubscribeAsync(
        IDataProtectionKeyObserver observer,
        IReadOnlyList<string> knownKeys,
        CancellationToken cancellationToken);

    Task UnsubscribeAsync(IDataProtectionKeyObserver observer, CancellationToken cancellationToken);

    Task<IReadOnlyList<string>> GetAllAsync();

    Task StoreAsync(string elementXml, string? friendlyName);
}
