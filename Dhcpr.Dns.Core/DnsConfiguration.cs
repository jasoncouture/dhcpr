using System.Diagnostics.CodeAnalysis;
using System.Net;
using Dhcpr.Core;

namespace Dhcpr.Dns.Core;

public class DnsConfiguration : IValidateSelf
{
    public RootServerConfiguration RootServers { get; set; } = new();

    public string[] ListenAddresses { get; set; } =
    {
        "127.0.0.1:53",
        "[::1]:53"
    };
    public string[] Forwarders { get; set; } =
    {
        "8.8.8.8",
        "8.8.4.4",
        "1.1.1.1",
        "1.0.0.1"
    };

    public bool UseParallelResolver { get; set; } = true;
    
    private const int DefaultDnsPort = 53;

    public IPEndPoint[] GetListenEndpoints() => GetEndpoints(ListenAddresses, DefaultDnsPort);

    private IPEndPoint[] GetEndpoints(string[] addresses, int defaultPort)
    {
        var endPoints = new IPEndPoint[addresses.Length];
        for (var x = 0; x < addresses.Length; x++)
        {
            endPoints[x] = addresses[x].GetEndpoint(53);
        }

        return endPoints;
    }

    public IPEndPoint[] GetForwarderEndpoints() => GetEndpoints(Forwarders, DefaultDnsPort);

    [SuppressMessage("ReSharper", "ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract", Justification = "Values are set by reflection")]
    public bool Validate()
    {
        if (Forwarders is null) return false;
        foreach (var forwarder in Forwarders)
        {
            if (!IPEndPoint.TryParse(forwarder, out _) && !IPAddress.TryParse(forwarder, out _))
                return false;
        }

        return RootServers.Validate();
    }
}