namespace Dhcpr.Server.Orleans.DataProtection;

public interface IDataProtectionKeyGrain : IGrainWithIntegerKey
{
    Task<IReadOnlyList<string>> GetAllAsync();

    Task StoreAsync(string elementXml, string? friendlyName);
}
