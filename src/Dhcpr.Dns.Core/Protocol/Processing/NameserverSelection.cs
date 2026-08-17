using System.Net;
using System.Net.Sockets;

namespace Dhcpr.Dns.Core.Protocol.Processing;

public static class NameserverSelection
{
    /// <summary>
    /// True for socket/IO failures (e.g. ENETUNREACH) that mean "try another nameserver",
    /// not "the DNS name itself failed".
    /// </summary>
    public static bool IsTransportFailure(Exception exception)
    {
        switch (exception)
        {
            case SocketException:
            case IOException:
                return true;
            case InvalidOperationException { InnerException: { } inner }:
                return IsTransportFailure(inner);
            case AggregateException aggregate:
                var flattened = aggregate.Flatten().InnerExceptions;
                return flattened.Count > 0 && flattened.All(IsTransportFailure);
            default:
                return false;
        }
    }

    /// <summary>
    /// IPv4 first, then IPv6, preserving relative order within each family.
    /// A shuffled first batch of AAAA-only roots waits the full UDP timeout when v6 is blackholed.
    /// </summary>
    public static IEnumerable<IPEndPoint> PreferIPv4(IEnumerable<IPEndPoint> endpoints)
    {
        var snapshot = endpoints as IList<IPEndPoint> ?? endpoints.ToList();
        for (var i = 0; i < snapshot.Count; i++)
        {
            if (snapshot[i].AddressFamily == AddressFamily.InterNetwork)
                yield return snapshot[i];
        }

        for (var i = 0; i < snapshot.Count; i++)
        {
            if (snapshot[i].AddressFamily == AddressFamily.InterNetworkV6)
                yield return snapshot[i];
        }
    }
}
