using System.Collections.Immutable;
using System.Net;

using Dhcpr.Core.Linq;

namespace Dhcpr.Dhcp.Core.Client;

public record DhcpSubnet(
    IPNetwork Network,
    ImmutableArray<IPAddressRange> AddressRanges
) : IDhcpSubnet
{
    public IPAddress? SelectAddress(IEnumerable<IPAddress> usedAddresses, IPNetwork network)
    {
        if (!Network.Contains(network.Address)) return null;
        using var availableAddressRanges =
            AddressRanges
            .Where(i => network.Contains(i.StartAddress) && network.Contains(i.EndAddress))
            .ToPooledList();
        using var usedAddressesPooledList = usedAddresses.ToPooledList();

        while (availableAddressRanges.Count != 0)
        {
            var rangeIndex = Random.Shared.Next(0, availableAddressRanges.Count);
            var currentRange = availableAddressRanges[rangeIndex];
            var selected = currentRange.SelectAddress(usedAddressesPooledList);
            if (selected is not null) return selected;
            availableAddressRanges.Remove(currentRange);
        }

        return null;
    }
}