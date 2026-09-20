namespace Dhcpr.Dns.Core.Protocol.Processing;

public sealed class DnsListenerReadiness : IDnsListenerReadiness
{
    private readonly Lock _sync = new();
    private string[] _expected = [];
    private readonly HashSet<string> _bound = [];

    public bool AllBound
    {
        get
        {
            lock (_sync)
                return _expected.Length > 0 && _bound.IsSupersetOf(_expected);
        }
    }

    public IReadOnlyList<string> Pending
    {
        get
        {
            lock (_sync)
                return _expected.Where(name => !_bound.Contains(name)).ToArray();
        }
    }

    public void SetExpected(IReadOnlyCollection<string> names)
    {
        ArgumentNullException.ThrowIfNull(names);
        lock (_sync)
        {
            _expected = names.ToArray();
            _bound.Clear();
        }
    }

    public void MarkBound(string name)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        lock (_sync)
            _bound.Add(name);
    }
}
