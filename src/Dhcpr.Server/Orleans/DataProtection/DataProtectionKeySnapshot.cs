namespace Dhcpr.Server.Orleans.DataProtection;

/// <summary>
/// Silo-local copy of the Data Protection key ring. The grain is the
/// cluster copy; this is what we read and what we use to bootstrap a
/// new activation on this node.
/// </summary>
internal static class DataProtectionKeySnapshot
{
    private static readonly object Gate = new();
    private static string[] _xml = [];

    public static string[] Copy()
    {
        lock (Gate)
            return [.. _xml];
    }

    public static void Replace(IEnumerable<string> xml)
    {
        ArgumentNullException.ThrowIfNull(xml);
        lock (Gate)
            _xml = [.. xml];
    }

    public static void Add(string elementXml)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(elementXml);
        lock (Gate)
        {
            if (Array.IndexOf(_xml, elementXml) >= 0)
                return;
            _xml = [.. _xml, elementXml];
        }
    }

    internal static void Clear()
    {
        lock (Gate)
            _xml = [];
    }
}
