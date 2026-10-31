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
public sealed class DataProtectionKeyFiles : IDataProtectionKeyFiles
{
    private readonly IDataProtectionKeySnapshot _snapshot;
    private readonly FileSystemXmlRepository _files;

    public DataProtectionKeyFiles(IDataProtectionKeySnapshot snapshot, IOptions<ApplicationConfiguration> configuration)
    {
        _snapshot = snapshot;
        var directory = Directory.CreateDirectory(configuration.Value.GetDataProtectionKeysPath());
        _files = new FileSystemXmlRepository(directory, NullLoggerFactory.Instance);
        foreach (var element in _files.GetAllElements())
            _snapshot.Add(element.ToString(SaveOptions.DisableFormatting));
    }

    public void Store(XElement element, string friendlyName)
    {
        _files.StoreElement(element, friendlyName);
        _snapshot.Add(element.ToString(SaveOptions.DisableFormatting));
    }

    public void Replace(IEnumerable<string> elementXml)
    {
        var incoming = elementXml as IReadOnlyCollection<string> ?? elementXml.ToArray();
        var known = _snapshot.Copy();
        foreach (var xml in incoming)
        {
            if (string.IsNullOrWhiteSpace(xml) || known.Contains(xml))
                continue;
            var element = XElement.Parse(xml);
            if (AlreadyStored(element))
                continue;
            try
            {
                _files.StoreElement(element, FriendlyName(element));
            }
            catch (IOException) when (AlreadyStored(element))
            {
                // File.Copy throws when the destination exists. Another silo wrote it first.
            }
        }

        _snapshot.Replace(incoming);
    }

    private bool AlreadyStored(XElement element)
    {
        var id = element.Attribute("id")?.Value;
        foreach (var existing in _files.GetAllElements())
        {
            if (id is not null && existing.Attribute("id")?.Value == id)
                return true;
            if (id is null && XNode.DeepEquals(existing, element))
                return true;
        }

        return false;
    }

    private static string FriendlyName(XElement element)
    {
        var id = element.Attribute("id")?.Value;
        if (id is not null && IsSafeFilename(id))
            return id;
        return Guid.NewGuid().ToString("N");
    }

    private static bool IsSafeFilename(string filename)
    {
        if (filename.Length == 0)
            return false;
        foreach (var c in filename)
        {
            if (c is not ('-' or '_' or (>= '0' and <= '9') or (>= 'A' and <= 'Z') or (>= 'a' and <= 'z')))
                return false;
        }

        return true;
    }
}
