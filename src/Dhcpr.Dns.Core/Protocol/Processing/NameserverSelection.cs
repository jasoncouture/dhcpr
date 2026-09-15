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
}
