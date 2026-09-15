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

    public Task<IReadOnlyList<string>> GetAllAsync()
        => Task.FromResult<IReadOnlyList<string>>(_elements.ToArray());

    public Task StoreAsync(string elementXml, string? friendlyName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(elementXml);
        _elements.Add(elementXml);
        return Task.CompletedTask;
    }
}
