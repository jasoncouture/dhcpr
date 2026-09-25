using System.Xml.Linq;

using Dhcpr.Core;

using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Dhcpr.Server.Orleans.DataProtection;

/// <summary>
/// Data Protection keys on disk. The process can load and create keys
/// while the Orleans grain has no live silo.
/// </summary>
public sealed class DataProtectionKeyFiles
{
    private readonly FileSystemXmlRepository _files;

    public DataProtectionKeyFiles(IOptions<ApplicationConfiguration> configuration)
    {
        var directory = Directory.CreateDirectory(configuration.Value.GetDataProtectionKeysPath());
        _files = new FileSystemXmlRepository(directory, NullLoggerFactory.Instance);
        foreach (var element in _files.GetAllElements())
            DataProtectionKeySnapshot.Add(element.ToString(SaveOptions.DisableFormatting));
    }

    public void Store(XElement element, string friendlyName)
    {
        _files.StoreElement(element, friendlyName);
        DataProtectionKeySnapshot.Add(element.ToString(SaveOptions.DisableFormatting));
    }

    public void Replace(IEnumerable<string> elementXml)
    {
        var incoming = elementXml as IReadOnlyCollection<string> ?? elementXml.ToArray();
        var known = DataProtectionKeySnapshot.Copy();
        foreach (var xml in incoming)
        {
            if (string.IsNullOrWhiteSpace(xml) || known.Contains(xml))
                continue;
            _files.StoreElement(XElement.Parse(xml), "key");
        }

        DataProtectionKeySnapshot.Replace(incoming);
    }
}
