namespace Dhcpr.Peering.Discovery;

public interface IPeeringMethod
{
    PeerDiscoveryMethod Method { get; }
    void Enable();
    void Disable();
    bool Enabled { get; }
    event EventHandler<PeerChangedEventArgs> PeerStateChanged;
    ValueTask<IEnumerable<Uri>> GetPeersAsync(CancellationToken cancellationToken);
}