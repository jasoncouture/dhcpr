using System.Net;

namespace Dhcpr.Dhcp.Core.Client;

public interface IDhcpSubnet
{
    /// <summary>
    /// The network this subnet serves.
    /// </summary>
    public DhcpNetwork Network { get; }

    /// <summary>
    /// Picks an unused address from <paramref name="network"/>, or <see langword="null"/> if none is available
    /// or <paramref name="network"/> does not match this subnet.
    /// </summary>
    public IPAddress? SelectAddress(IEnumerable<IPAddress> usedAddresses, DhcpNetwork network);
}