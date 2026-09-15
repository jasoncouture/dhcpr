using System.Xml.Linq;

namespace Dhcpr.Server.Orleans.DataProtection;

/// <summary>
/// Silo-local key ring. Writes allocate; reads return the current
/// arrays without cloning or parsing.
/// </summary>
internal static class DataProtectionKeySnapshot
{
    private static readonly object Gate = new();
    private static readonly State Empty = new([], []);
    private static State _state = Empty;

    public static string[] Copy() => Volatile.Read(ref _state).Xml;

    public static IReadOnlyCollection<XElement> Get() => Volatile.Read(ref _state).Elements;

    public static void Replace(IEnumerable<string> xml)
    {
        ArgumentNullException.ThrowIfNull(xml);
        Volatile.Write(ref _state, FromXml(xml));
    }

    public static void Add(string elementXml)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(elementXml);
        lock (Gate)
        {
            var current = _state;
            if (Array.IndexOf(current.Xml, elementXml) >= 0)
                return;
            Volatile.Write(ref _state, current.Append(elementXml));
        }
    }

    internal static void Clear() => Volatile.Write(ref _state, Empty);

    private static State FromXml(IEnumerable<string> xml)
    {
        var strings = xml as string[] ?? [.. xml];
        var elements = new XElement[strings.Length];
        for (var i = 0; i < strings.Length; i++)
            elements[i] = XElement.Parse(strings[i]);
        return new State(strings, elements);
    }

    private sealed record State(string[] Xml, XElement[] Elements)
    {
        public State Append(string elementXml)
        {
            var xml = new string[Xml.Length + 1];
            Xml.CopyTo(xml, 0);
            xml[^1] = elementXml;

            var elements = new XElement[Elements.Length + 1];
            Elements.CopyTo(elements, 0);
            elements[^1] = XElement.Parse(elementXml);
            return new State(xml, elements);
        }
    }
}
