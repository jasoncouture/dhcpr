using System.Xml.Linq;

using Microsoft.AspNetCore.DataProtection.Repositories;

namespace Dhcpr.Server.Orleans.DataProtection;

/// <summary>
/// ASP.NET Data Protection <see cref="IXmlRepository"/>. Reads the
/// silo-local snapshot. Writes go to the grain, which pushes the ring
/// to every subscriber. Sync because the DP API is sync.
/// </summary>
public sealed class OrleansDataProtectionKeyRepository : IXmlRepository
{
    private readonly IGrainFactory _grains;

    public OrleansDataProtectionKeyRepository(IGrainFactory grains)
    {
        _grains = grains;
    }

    public IReadOnlyCollection<XElement> GetAllElements()
        => DataProtectionKeySnapshot.Get();

    public void StoreElement(XElement element, string friendlyName)
    {
        var xml = element.ToString(SaveOptions.DisableFormatting);
        Grain()
            .StoreAsync(xml, friendlyName)
            .GetAwaiter()
            .GetResult();
        DataProtectionKeySnapshot.Add(xml);
    }

    private IDataProtectionKeyGrain Grain()
        => _grains.GetGrain<IDataProtectionKeyGrain>(DataProtectionKeyGrain.Key);
}
