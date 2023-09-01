namespace Dhcpr.Peering.Discovery;

public class PeerChangedEventArgs : EventArgs
{
    public required Uri Uri { get; init; }
    public required PeerChange State { get; init; }
}