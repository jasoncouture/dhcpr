using System.Diagnostics.CodeAnalysis;
using System.Net;

using Dhcpr.Core;
using Dhcpr.Core.Linq;
using Dhcpr.Dns.Core.Resolvers.Caching;

using DNS.Protocol;
using DNS.Protocol.ResourceRecords;

namespace Dhcpr.Dns.Core;

public class ForwarderConfiguration : IValidateSelf
{
    public string[] Addresses { get; set; } = Array.Empty<string>();
    public bool Parallel { get; set; } = true;
    public bool Enabled { get; set; } = true;
    public IPEndPoint[] GetForwarderEndpoints() => Addresses.GetEndPoints();

    public bool Validate()
    {
        return Addresses.AreAllEndPointsValid();
    }
}

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

public sealed class DnsConfiguration : IValidateSelf
{
    public RootServerConfiguration RootServers { get; set; } = new();
    public ForwarderConfiguration Forwarders { get; set; } = new();

    public IPEndPoint[] GetListenEndpoints() => ListenAddresses.GetEndPoints();
    public string[] ListenAddresses { get; set; } = { "127.0.0.1:53" };


    [SuppressMessage("ReSharper", "ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract",
        Justification = "Values are set by reflection")]
    public bool Validate()
    {
        if (Forwarders is null) return false;

        return ListenAddresses.AreAllEndPointsValid() &&
               Forwarders.Validate() &&
               RootServers.Validate();
    }
}