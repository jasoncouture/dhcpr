using System.Diagnostics.CodeAnalysis;

using Dhcpr.Dhcp.Core.Protocol;

namespace Dhcpr.Dhcp.Core.Client;

public interface IDhcpLeasePool
{
    IEnumerable<DhcpClientLease> ClientLeases { get; }
    bool TryGetDhcpLease(HardwareAddress address, [NotNullWhen(true)] out DhcpClientLease? lease);
    bool TrySetLease(DhcpClientLease lease);
    DhcpClientLease? TryCreateLease(HardwareAddress address, IPNetwork network);
    bool TryRemoveLease(DhcpClientLease lease);
}