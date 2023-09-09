using System.Net;

using Dhcpr.Core;
using Dhcpr.Core.Linq;
using Dhcpr.Dns.Core.Resolvers.Caching;

using DNS.Protocol;
using DNS.Protocol.ResourceRecords;

namespace Dhcpr.Dns.Core;

static class DnsExtensions
{
    public const int DefaultDnsPort = 53;

    public static void CloneInPlace(this IList<IResourceRecord> records)
    {
        using var temporaryRecordList = records.ToPooledList();
        records.Clear();
        foreach(var record in temporaryRecordList)
            records.Add(record.Clone());
    }
    public static IResponse Clone(this IResponse response, bool deep = false)
    {
        if (deep)
        {
            response = response.Clone();
            response.AnswerRecords.CloneInPlace();
            response.AdditionalRecords.CloneInPlace();
            response.AuthorityRecords.CloneInPlace();
            return response;
        }
        if (response is NoCacheResponse)
            return new NoCacheResponse(new Response(response));

        return new Response(response);
    }

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