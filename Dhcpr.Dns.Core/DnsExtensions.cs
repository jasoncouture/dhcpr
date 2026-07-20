using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

using Dhcpr.Core;

namespace Dhcpr.Dns.Core;

public static class DnsExtensions
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

    public static bool AreAllListenAddressesValid(this IEnumerable<string> addresses)
    {
        foreach (var address in addresses)
        {
            if (!TryParseListenAddress(address, out _))
                return false;
        }

        return true;
    }

    public static bool TryParseListenAddress(string value, out DnsListenEndpoint endpoint)
    {
        endpoint = default;
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri))
            return false;

        var host = uri.DnsSafeHost;
        if (string.IsNullOrWhiteSpace(host))
            return false;

        var port = uri.Port > 0 ? uri.Port : DefaultDnsPort;

        switch (uri.Scheme.ToLowerInvariant())
        {
            case "udp":
                endpoint = new DnsListenEndpoint(DnsListenProtocol.Udp, host, port);
                return true;
            case "tcp":
                endpoint = new DnsListenEndpoint(DnsListenProtocol.Tcp, host, port);
                return true;
            case "interface":
                endpoint = new DnsListenEndpoint(DnsListenProtocol.Both, host, port, IsNetworkInterface: true);
                return true;
            default:
                return false;
        }
    }

    public static DnsListenEndpoint[] GetListenEndpoints(this string[] addresses)
    {
        var endPoints = new DnsListenEndpoint[addresses.Length];
        for (var x = 0; x < addresses.Length; x++)
        {
            if (!TryParseListenAddress(addresses[x], out endPoints[x]))
                throw new InvalidOperationException($"Invalid DNS listen address: \"{addresses[x]}\"");
        }

        return endPoints;
    }

    public static IReadOnlyList<string> GetNetworkInterfaceNames()
        => NetworkInterface.GetAllNetworkInterfaces()
            .Select(i => i.Name)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(i => i, StringComparer.OrdinalIgnoreCase)
            .ToArray();

    public static IPAddress[] GetNetworkInterfaceAddresses(string interfaceName)
    {
        var networkInterface = NetworkInterface.GetAllNetworkInterfaces()
            .FirstOrDefault(i => i.Name.Equals(interfaceName, StringComparison.OrdinalIgnoreCase));

        if (networkInterface is null)
            return Array.Empty<IPAddress>();

        return networkInterface.GetIPProperties().UnicastAddresses
            .Select(i => i.Address)
            .Where(i => i.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6)
            .Where(i => !i.IsIPv6LinkLocal)
            .ToArray();
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
