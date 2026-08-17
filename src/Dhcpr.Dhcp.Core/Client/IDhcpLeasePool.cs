using System.Diagnostics.CodeAnalysis;

using Dhcpr.Dhcp.Core.Protocol;

namespace Dhcpr.Dhcp.Core.Client;

public interface IDhcpLeasePool
{
    /// <summary>
    /// All leases currently held by the pool.
    /// </summary>
    IEnumerable<DhcpClientLease> ClientLeases { get; }

    /// <summary>
    /// Looks up a lease by client hardware address.
    /// </summary>
    /// <returns><see langword="true"/> when a lease exists for <paramref name="address"/>.</returns>
    bool TryGetDhcpLease(HardwareAddress address, [NotNullWhen(true)] out DhcpClientLease? lease);

    /// <summary>
    /// Stores <paramref name="lease"/>, keeping the newer <see cref="DhcpClientLease.Created"/> when one already exists.
    /// </summary>
    /// <returns><see langword="true"/> when <paramref name="lease"/> is the stored value.</returns>
    bool TrySetLease(DhcpClientLease lease);

    /// <summary>
    /// Creates a new lease for <paramref name="address"/> on <paramref name="network"/>,
    /// or <see langword="null"/> if a lease already exists or no address is available.
    /// </summary>
    DhcpClientLease? TryCreateLease(HardwareAddress address, DhcpNetwork network);

    /// <summary>
    /// Removes <paramref name="lease"/> when it is still the current lease for that client.
    /// </summary>
    /// <returns><see langword="true"/> when the lease is gone after this call.</returns>
    bool TryRemoveLease(DhcpClientLease lease);
}