using System.Collections.Immutable;
using System.Xml.Linq;

namespace Dhcpr.Server.Orleans.DataProtection;

/// <inheritdoc cref="IDataProtectionKeySnapshot"/>
public sealed class DataProtectionKeySnapshot : IDataProtectionKeySnapshot
{
    private readonly object _gate = new();
    private ImmutableHashSet<string> _xml = [];
    private XElement[] _elements = [];

    public ImmutableHashSet<string> Copy() => _xml;

    public IReadOnlyCollection<XElement> Get() => _elements;

    public void Replace(IEnumerable<string> xml)
    {
        ArgumentNullException.ThrowIfNull(xml);
        lock (_gate)
        {
            _xml = xml.ToImmutableHashSet();
            _elements = Parse(_xml);
        }
    }

    public void Add(string elementXml)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(elementXml);
        lock (_gate)
        {
            _xml = _xml.Add(elementXml);
            _elements = Parse(_xml);
        }
    }

    public void Clear()
    {
        lock (_gate)
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
