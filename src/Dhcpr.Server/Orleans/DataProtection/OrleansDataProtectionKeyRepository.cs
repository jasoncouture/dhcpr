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
    private readonly IDataProtectionKeyFiles _files;
    private readonly IDataProtectionKeySnapshot _snapshot;

    public OrleansDataProtectionKeyRepository(IDataProtectionKeyFiles files, IDataProtectionKeySnapshot snapshot)
    {
        _files = files;
        _snapshot = snapshot;
    }

    public IReadOnlyCollection<XElement> GetAllElements()
        => _snapshot.Get();

    public void StoreElement(XElement element, string friendlyName)
        => _files.Store(element, friendlyName);
}
