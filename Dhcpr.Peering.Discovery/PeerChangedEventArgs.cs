namespace Dhcpr.Peering.Discovery;

public sealed class PeerChangedEventArgs : EventArgs
{
    public required Uri Uri { get; init; }
    public required PeerChange State { get; init; }
}