using System.Net;

using Dhcpr.Core.Linq;
using Dhcpr.Dns.Core.Protocol;

namespace Dhcpr.Dns.Core.Protocol.Processing;

public interface IReferralWalker
{
    /// <summary>
    /// Follows NS referrals from <paramref name="endPoints"/> until an answer, NXDOMAIN, or hop limit.
    /// </summary>
    ValueTask<DomainMessage> FollowAsync(
        DomainMessageContext context,
        DomainMessage request,
        PooledList<IPEndPoint> endPoints,
        CancellationToken cancellationToken,
        ReferralWalkOptions? options = null);

    /// <summary>
    /// Fills <paramref name="endPoints"/> from NS names and glue in <paramref name="referral"/>.
    /// </summary>
    /// <returns><see langword="true"/> when at least one endpoint was added.</returns>
    ValueTask<bool> TrySeedEndpointsAsync(
        DomainMessageContext context,
        DomainMessage referral,
        PooledList<IPEndPoint> endPoints,
        CancellationToken cancellationToken,
        ReferralWalkOptions? options = null);

    /// <summary>
    /// Resolves A and AAAA for <paramref name="nsNames"/> via the internal client.
    /// When <paramref name="ignoreDnssecStatus"/> is <see langword="true"/>, side-lookup status does not update the parent scope.
    /// </summary>
    ValueTask<IReadOnlyList<IPAddress>> ResolveNameserverAddressesAsync(
        DomainMessageContext context,
        IReadOnlyList<string> nsNames,
        CancellationToken cancellationToken,
        bool ignoreDnssecStatus = true);

    /// <summary>
    /// Returns NS target names from <paramref name="records"/>.
    /// </summary>
    IEnumerable<string> GetNameserverNames(IEnumerable<DomainResourceRecord> records);

    /// <summary>
    /// Returns NS target names from <paramref name="records"/> whose owner is <paramref name="qname"/> or a parent of it.
    /// </summary>
    IEnumerable<string> GetNameserverNames(
        IEnumerable<DomainResourceRecord> records,
        DomainLabels qname);

    /// <summary>
    /// Returns A/AAAA glue from <paramref name="records"/> whose owner is in <paramref name="nsNames"/>.
    /// </summary>
    IEnumerable<IPAddress> GetGlueAddresses(
        IEnumerable<DomainResourceRecord> records,
        HashSet<string> nsNames);
}
