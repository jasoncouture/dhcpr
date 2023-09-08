using System.Net;

namespace Dhcpr.Dhcp.Core.Client;

public interface IDhcpSubnet
{
    public IPNetwork Network { get; }
    public IPAddress? SelectAddress(IEnumerable<IPAddress> usedAddresses, IPNetwork network);

}