using System.Net;

namespace Dhcpr.Dhcp.Core.Client;

public interface IDhcpSubnet
{
    public DhcpNetwork Network { get; }
    public IPAddress? SelectAddress(IEnumerable<IPAddress> usedAddresses, DhcpNetwork network);

}