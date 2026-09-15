namespace Dhcpr.Server.Orleans.DataProtection;

/// <summary>
/// In-memory key ring for ASP.NET Data Protection. Shared across silos
/// while this activation lives. Not persisted — a new activation is empty.
/// </summary>
[KeepAlive]
public sealed class DataProtectionKeyGrain : Grain, IDataProtectionKeyGrain
{
    public const long Key = 0;

    private readonly List<string> _elements = [];

    public async Task<IReadOnlyList<string>> GetAllAsync()
    {
        await Task.Yield();
        return _elements.ToArray();
    }

    public async Task StoreAsync(string elementXml, string? friendlyName)
    {
        await Task.Yield();
        ArgumentException.ThrowIfNullOrWhiteSpace(elementXml);
        _elements.Add(elementXml);
    }
}
