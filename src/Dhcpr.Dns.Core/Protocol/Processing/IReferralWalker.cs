using System.Net;

using Dhcpr.Core.Linq;
using Dhcpr.Dns.Core.Protocol;

namespace Dhcpr.Dns.Core.Protocol.Processing;

public interface IReferralWalker
{
    ValueTask<DomainMessage> FollowAsync(
        DomainMessageContext context,
        DomainMessage request,
        PooledList<IPEndPoint> endPoints,
        CancellationToken cancellationToken);

    ValueTask<IReadOnlyList<IPAddress>> ResolveNameserverAddressesAsync(
        DomainMessageContext context,
        IReadOnlyList<string> nsNames,
        CancellationToken cancellationToken);

    IEnumerable<string> GetNameserverNames(
        IEnumerable<DomainResourceRecord> records,
        DomainLabels qname);

    IEnumerable<IPAddress> GetGlueAddresses(
        IEnumerable<DomainResourceRecord> records,
        HashSet<string> nsNames);
}
