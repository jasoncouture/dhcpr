using System.Collections.Immutable;
using System.Xml.Linq;

namespace Dhcpr.Server.Orleans.DataProtection;

/// <summary>
/// Silo-local key ring. Writes allocate; reads return the current
/// set and parsed elements without cloning.
/// </summary>
public interface IDataProtectionKeySnapshot
{
    ImmutableHashSet<string> Copy();

    IReadOnlyCollection<XElement> Get();

    void Replace(IEnumerable<string> xml);

    void Add(string elementXml);

    void Clear();
}
