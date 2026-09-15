using System.Collections.Immutable;
using System.Xml.Linq;

namespace Dhcpr.Server.Orleans.DataProtection;

/// <summary>
/// Silo-local key ring. Writes allocate; reads return the current
/// set and parsed elements without cloning.
/// </summary>
internal static class DataProtectionKeySnapshot
{
    private static readonly object Gate = new();
    private static ImmutableHashSet<string> _xml = [];
    private static XElement[] _elements = [];

    public static ImmutableHashSet<string> Copy() => _xml;

    public static IReadOnlyCollection<XElement> Get() => _elements;

    public static void Replace(IEnumerable<string> xml)
    {
        ArgumentNullException.ThrowIfNull(xml);
        lock (Gate)
        {
            _xml = xml.ToImmutableHashSet();
            _elements = Parse(_xml);
        }
    }

    public static void Add(string elementXml)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(elementXml);
        lock (Gate)
        {
            _xml = _xml.Add(elementXml);
            _elements = Parse(_xml);
        }
    }

    internal static void Clear()
    {
        lock (Gate)
        {
            _xml = [];
            _elements = [];
        }
    }

    private static XElement[] Parse(ImmutableHashSet<string> xml)
    {
        var elements = new XElement[xml.Count];
        var i = 0;
        foreach (var item in xml)
            elements[i++] = XElement.Parse(item);
        return elements;
    }
}
