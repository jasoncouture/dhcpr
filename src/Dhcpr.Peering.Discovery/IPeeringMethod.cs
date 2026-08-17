namespace Dhcpr.Peering.Discovery;

public interface IPeeringMethod
{
    /// <summary>
    /// The discovery mechanism this implementation provides.
    /// </summary>
    PeerDiscoveryMethod Method { get; }

    /// <summary>
    /// Starts peer discovery.
    /// </summary>
    void Enable();

    /// <summary>
    /// Stops peer discovery.
    /// </summary>
    void Disable();

    /// <summary>
    /// <see langword="true"/> when this method is actively discovering peers.
    /// </summary>
    bool Enabled { get; }

    /// <summary>
    /// Raised when a peer is added or removed while this method is enabled.
    /// </summary>
    event EventHandler<PeerChangedEventArgs> PeerStateChanged;

    /// <summary>
    /// Returns the peers currently known to this method.
    /// </summary>
    ValueTask<IEnumerable<Uri>> GetPeersAsync(CancellationToken cancellationToken);
}