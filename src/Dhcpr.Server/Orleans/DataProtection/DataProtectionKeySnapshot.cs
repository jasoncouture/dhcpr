namespace Dhcpr.Server.Orleans.DataProtection;

/// <summary>
/// Silo-local key ring. Orleans already copies on the wire; this
/// holds that enumerable and hands it out as <see cref="IEnumerable{T}"/>
/// so callers cannot mutate it without a cast.
/// </summary>
internal static class DataProtectionKeySnapshot
{
    private static readonly object Gate = new();
    private static IEnumerable<string> _xml = [];

    public static IEnumerable<string> Get()
    {
        lock (Gate)
            return _xml;
    }

    public static void Replace(IEnumerable<string> xml)
    {
        ArgumentNullException.ThrowIfNull(xml);
        lock (Gate)
            _xml = xml;
    }

    public static void Add(string elementXml)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(elementXml);
        lock (Gate)
        {
            if (_xml is HashSet<string> set)
            {
                set.Add(elementXml);
                return;
            }

            var next = new HashSet<string>(_xml);
            next.Add(elementXml);
            _xml = next;
        }
    }

    internal static void Clear()
    {
        lock (Gate)
            _xml = [];
    }
}
