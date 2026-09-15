using System.Xml.Linq;

using Microsoft.AspNetCore.DataProtection.Repositories;

namespace Dhcpr.Server.Orleans.DataProtection;

/// <summary>
/// ASP.NET Data Protection <see cref="IXmlRepository"/> backed by a single
/// Orleans grain. Sync because the DP API is sync.
/// </summary>
public sealed class OrleansDataProtectionKeyRepository : IXmlRepository
{
    private readonly IGrainFactory _grains;

    public OrleansDataProtectionKeyRepository(IGrainFactory grains)
    {
        _grains = grains;
    }

    public IReadOnlyCollection<XElement> GetAllElements()
    {
        var xml = Grain().GetAllAsync().GetAwaiter().GetResult();
        var elements = new List<XElement>(xml.Count);
        foreach (var item in xml)
            elements.Add(XElement.Parse(item));
        return elements;
    }

    public void StoreElement(XElement element, string friendlyName)
        => Grain()
            .StoreAsync(element.ToString(SaveOptions.DisableFormatting), friendlyName)
            .GetAwaiter()
            .GetResult();

    private IDataProtectionKeyGrain Grain()
        => _grains.GetGrain<IDataProtectionKeyGrain>(DataProtectionKeyGrain.Key);
}
