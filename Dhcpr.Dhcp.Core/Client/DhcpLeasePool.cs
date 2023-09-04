using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Net;

using Dhcpr.Core.Linq;
using Dhcpr.Dhcp.Core.Protocol;

namespace Dhcpr.Dhcp.Core.Client;

public class DhcpLeasePool : IDhcpLeasePool
{
    private readonly ConcurrentBag<IDhcpSubnet> _subnets;

    public DhcpLeasePool(IEnumerable<IDhcpSubnet> subnets)
    {
        _subnets = new ConcurrentBag<IDhcpSubnet>(subnets);
    }

    private readonly ConcurrentDictionary<string, DhcpClientLease> _leases = new();
    public IEnumerable<DhcpClientLease> ClientLeases => _leases.Values;

    public bool TryGetDhcpLease(HardwareAddress address, [NotNullWhen(true)] out DhcpClientLease? lease)
        => _leases.TryGetValue(address.ToString(), out lease);

    public bool TrySetLease(DhcpClientLease lease)
    {
        var output = _leases.AddOrUpdate(lease.HardwareAddress.ToString(), lease,
            (_, current) =>
                current.Created > lease.Created
                    ? current
                    : lease);

        return output == lease;
    }

    public DhcpClientLease? TryCreateLease(HardwareAddress address, IPNetwork network)
    {
        if (TryGetDhcpLease(address, out _)) return null;
        using var shuffledSubnets = _subnets.OrderBy(i => Guid.NewGuid()).ToPooledList();
        using var usedAddresses = _leases.Values
            .Where(i => network.Contains(i.Address))
            .Select(i => i.Address)
            .ToPooledList();
        foreach (var subnet in shuffledSubnets)
        {
            var selectedAddress = subnet.SelectAddress(usedAddresses, network);
            if (selectedAddress is not null)
            {
                var lease = new DhcpClientLease(address,
                    0,
                    network,
                    DateTimeOffset.Now,
                    DateTimeOffset.Now.AddMinutes(2),
                    DhcpClientState.Initial,
                    120,
                    selectedAddress,
                    IPAddress.Any,
                    ImmutableArray<IPAddress>.Empty,
                    DhcpOptionCollection.Empty
                );
                if (TrySetLease(lease))
                {
                    return lease;
                }
            }
        }

        return null;
    }


    public bool TryRemoveLease(DhcpClientLease lease)
    {
        // If the lease didn't exist, we return true because the lease passed in was valid compared
        // to our current state
        while (true)
        {
            if (!TryGetDhcpLease(lease.HardwareAddress, out var currentLease))
                return true;
            if (currentLease.Created > lease.Created) return false;
            var result = _leases.TryRemove(currentLease.HardwareAddress.ToString(), out var removedLease);
            // Same as above, already removed.
            if (!result) return true;

            Debug.Assert(removedLease != null, "removedLease != null");

            if (removedLease == currentLease)
                return true;

            TrySetLease(removedLease); // Put it back.
        }
    }
}