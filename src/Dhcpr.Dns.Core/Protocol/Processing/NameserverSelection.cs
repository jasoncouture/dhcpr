using System.Collections.Immutable;
using System.Net;
using System.Net.Sockets;

namespace Dhcpr.Dns.Core.Protocol.Processing;

public static class NameserverSelection
{
    /// <summary>
    /// Alternate IPv4 and IPv6 so an opening race is not all one family.
    /// First family follows <paramref name="endpoints"/>[0] — no preference.
    /// </summary>
    public static ImmutableArray<IPEndPoint> InterleaveFamilies(IReadOnlyList<IPEndPoint> endpoints)
    {
        if (endpoints.Count <= 1)
            return [..endpoints];

        List<IPEndPoint>? v4 = null;
        List<IPEndPoint>? v6 = null;
        foreach (var endPoint in endpoints)
        {
            if (endPoint.AddressFamily == AddressFamily.InterNetworkV6)
                (v6 ??= []).Add(endPoint);
            else
                (v4 ??= []).Add(endPoint);
        }

        if (v4 is null || v6 is null)
            return [..endpoints];

        var result = new IPEndPoint[endpoints.Count];
        var i = 0;
        var i4 = 0;
        var i6 = 0;
        var v6First = endpoints[0].AddressFamily == AddressFamily.InterNetworkV6;
        while (i4 < v4.Count || i6 < v6.Count)
        {
            if (v6First)
            {
                if (i6 < v6.Count) result[i++] = v6[i6++];
                if (i4 < v4.Count) result[i++] = v4[i4++];
            }
            else
            {
                if (i4 < v4.Count) result[i++] = v4[i4++];
                if (i6 < v6.Count) result[i++] = v6[i6++];
            }
        }

        return [..result];
    }

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
}
