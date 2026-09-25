using System.Xml.Linq;

using Microsoft.AspNetCore.DataProtection.Repositories;

namespace Dhcpr.Server.Orleans.DataProtection;

/// <summary>
/// ASP.NET Data Protection <see cref="IXmlRepository"/>. Reads the
/// silo-local snapshot, which is filled from disk at startup. Writes
/// hit disk before any grain replication. Sync because the DP API is sync.
/// </summary>
public sealed class OrleansDataProtectionKeyRepository : IXmlRepository
{
    private readonly DataProtectionKeyFiles _files;

    public OrleansDataProtectionKeyRepository(DataProtectionKeyFiles files)
    {
        _files = files;
    }

    public IReadOnlyCollection<XElement> GetAllElements()
        => DataProtectionKeySnapshot.Get();

    public void StoreElement(XElement element, string friendlyName)
        => _files.Store(element, friendlyName);
}
