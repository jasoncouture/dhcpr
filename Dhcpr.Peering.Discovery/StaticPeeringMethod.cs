using System.Collections.Immutable;

using Microsoft.Extensions.Options;

namespace Dhcpr.Peering.Discovery;

public class StaticPeeringMethod : IPeeringMethod, IDisposable
{
    private readonly HashSet<Uri> _currentPeers = new();
    private readonly IDisposable? _changeSubscription;

    public StaticPeeringMethod(IOptionsMonitor<StaticConfiguration> options)
    {
        OnConfigurationChanged(options.CurrentValue, null);
        _changeSubscription = options.OnChange(OnConfigurationChanged);
    }

    private void OnConfigurationChanged(StaticConfiguration configuration, string? _)
    {
        var peerChangedEventArgs = new List<PeerChangedEventArgs>();
        lock (_currentPeers)
        {
            var peersToRemove = _currentPeers.Except(configuration.Peers);
            var peersToAdd = configuration.Peers.Except(_currentPeers);

            foreach (var peer in peersToRemove)
            {
                if (_currentPeers.Remove(peer))
                    peerChangedEventArgs.Add(new PeerChangedEventArgs() { State = PeerChange.Lost, Uri = peer });
            }

            foreach (var peer in peersToAdd)
            {
                if (_currentPeers.Add(peer))
                    peerChangedEventArgs.Add(new PeerChangedEventArgs() { State = PeerChange.Discovered, Uri = peer });
            }
        }

        if (!Enabled) return;

        foreach (var peerState in peerChangedEventArgs)
        {
            OnPeerStateChanged(peerState);
        }
    }

    private void OnPeerStateChanged(PeerChangedEventArgs peerState)
    {
        PeerStateChanged?.Invoke(this, peerState);
    }

    public PeerDiscoveryMethod Method { get; } = PeerDiscoveryMethod.Configuration;

    public void Enable()
    {
        Enabled = true;
    }

    public void Disable()
    {
        Enabled = false;
    }

    public bool Enabled { get; private set; }
    public event EventHandler<PeerChangedEventArgs>? PeerStateChanged;

    public ValueTask<IEnumerable<Uri>> GetPeersAsync(CancellationToken cancellationToken)
    {
        IEnumerable<Uri> peers;
        lock (_currentPeers)
        {
            peers = _currentPeers.ToImmutableArray();
        }
        return ValueTask.FromResult(peers);
    }

    public void Dispose()
    {
        _changeSubscription?.Dispose();
    }
}