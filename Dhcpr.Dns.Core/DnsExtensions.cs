using System.Net;

using Dhcpr.Core;

namespace Dhcpr.Dns.Core;

static class DnsExtensions
{
    public const int DefaultDnsPort = 53;

    public static bool AreAllEndPointsValid(this IEnumerable<string> addresses)
    {
        foreach (var address in addresses)
        {
            if (!address.TryGetEndPoint(1, out var _))
                return false;
        }

        return true;
    }

    public static IPEndPoint[] GetEndPoints(this string[] addresses, int defaultPort = DefaultDnsPort)
    {
        var endPoints = new IPEndPoint[addresses.Length];
        for (var x = 0; x < addresses.Length; x++)
        {
            endPoints[x] = addresses[x].GetIPEndPoint(defaultPort);
        }

        return endPoints;
    }
}