using Dhcpr.Core;

namespace Dhcpr.Peering.Discovery;

public class PeeringConfiguration : IValidateSelf
{
    public int PeerCommunicationPort { get; set; } = PeeringConstants.DefaultClusterPort;
    public string[] PeerSubnets { get; set; } = Array.Empty<string>();
    public PeerDiscoveryMethod PeeringMethod { get; set; } = PeerDiscoveryMethod.None;

    public bool Validate()
    {
        if (PeerCommunicationPort > 65535 || PeerCommunicationPort <= 0)
            return false;

        return PeerSubnets.All(subnet => subnet.TryParseClasslessInterDomainRouting(out _, out _));
    }
}