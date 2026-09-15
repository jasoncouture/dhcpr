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

    public static ImmutableHashSet<string> Copy() => Volatile.Read(ref _xml);

    public static IReadOnlyCollection<XElement> Get() => Volatile.Read(ref _elements);

    public static void Replace(IEnumerable<string> xml)
    {
        ArgumentNullException.ThrowIfNull(xml);
        lock (Gate)
        {
            var set = xml.ToImmutableHashSet();
            Volatile.Write(ref _xml, set);
            Volatile.Write(ref _elements, Parse(set));
        }
    }

    public static void Add(string elementXml)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(elementXml);
        lock (Gate)
        {
            Volatile.Write(ref _xml, _xml.Add(elementXml));
            Volatile.Write(ref _elements, Parse(_xml));
        }
    }

    internal static void Clear()
    {
        lock (Gate)
        {
            Volatile.Write(ref _xml, []);
            Volatile.Write(ref _elements, []);
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
