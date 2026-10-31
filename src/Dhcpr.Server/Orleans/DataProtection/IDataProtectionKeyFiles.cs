using System.Xml.Linq;

namespace Dhcpr.Server.Orleans.DataProtection;

/// <summary>
/// Data Protection keys on disk.
/// </summary>
public interface IDataProtectionKeyFiles
{
    void Store(XElement element, string friendlyName);

    void Replace(IEnumerable<string> elementXml);
}
