namespace Dhcpr.Dns.Core.Protocol.Processing;

/// <summary>
/// Tracks which configured DNS sockets have called Bind/Start.
/// Ready is false until every expected listener is bound.
/// </summary>
public interface IDnsListenerReadiness
{
    bool AllBound { get; }

    IReadOnlyList<string> Pending { get; }

    void SetExpected(IReadOnlyCollection<string> names);

    void MarkBound(string name);
}
