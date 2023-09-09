using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

using Dhcpr.Core.Linq;

namespace Dhcpr.Core;

public static partial class NetworkExtensions
{
    public static bool IsInLocalSubnet(this IPAddress address)
    {
        if (IPAddress.IsLoopback(address)) return false;
        using var unicastAddresses = NetworkInterface.GetAllNetworkInterfaces().Select(i => i.GetIPProperties()).SelectMany(i => i.UnicastAddresses).ToPooledList().ToPooledList();
        using var possibleNetworks = unicastAddresses.Where(i => i.Address.AddressFamily == address.AddressFamily).ToPooledList();
        
        foreach (var network in possibleNetworks)
        {

            if (address.AddressFamily == AddressFamily.InterNetwork &&
                address.IsInNetwork(network.Address, network.IPv4Mask))
                return true;
            if (address.AddressFamily == AddressFamily.InterNetworkV6 &&
                address.IsInNetwork(network.Address, network.PrefixLength))
                return true;
        }

        return false;
    }

    public static IPAddress GetNetwork(this IPAddress address, IPAddress netmask)
    {
        if (address.AddressFamily != netmask.AddressFamily)
            throw new InvalidOperationException("Netmask and address must be the same address family");
        if (address.AddressFamily is not AddressFamily.InterNetwork and not AddressFamily.InterNetworkV6)
            throw new InvalidOperationException("Only IPv4 and IPv6 are supported.");
        var addressFamilyByteCount = address.AddressFamily == AddressFamily.InterNetwork ? 4 : 16;
        Span<byte> addressBytes = stackalloc byte[addressFamilyByteCount];
        Span<byte> netmaskBytes = stackalloc byte[addressFamilyByteCount];
        Span<byte> networkBytes = stackalloc byte[addressFamilyByteCount];
        address.TryWriteBytes(addressBytes, out _);
        netmask.TryWriteBytes(netmaskBytes, out _);

        for (var x = 0; x < addressFamilyByteCount; x++)
        {
            networkBytes[x] = (byte)(addressBytes[x] & netmaskBytes[x]);
        }

        return new IPAddress(networkBytes);
    }

    public static bool TryParseClasslessInterDomainRouting(this string input,
        [NotNullWhen(true)] out IPAddress? address, [NotNullWhen(true)] out IPAddress? subnet)
    {
        address = default;
        subnet = default;
        var parts = input.Split('/');
        if (parts.Length != 2) return false;
        if (!IPAddress.TryParse(parts[0], out address))
            return false;
        if (!int.TryParse(parts[1], out var maskBits))
            return false;
        if (maskBits > GetBitCount(address.AddressFamily) || maskBits < 0)
            return false;

        subnet = ClasslessInterDomainRoutingToNetworkMask(maskBits, address.AddressFamily);

        return true;
    }

    private static int GetBitCount(AddressFamily addressFamily)
    {
        if (addressFamily == AddressFamily.InterNetwork) return 32;
        if (addressFamily == AddressFamily.InterNetworkV6) return 128;

        return -1;
    }

    public static IPAddress ClasslessInterDomainRoutingToNetworkMask(this int bitCount, AddressFamily addressFamily)
    {
        if (addressFamily != AddressFamily.InterNetwork && addressFamily != AddressFamily.InterNetworkV6)
            throw new InvalidOperationException("Only IPv4 and IPv6 are supported.");
        if (bitCount < 0) throw new ArgumentOutOfRangeException(nameof(bitCount));
        if (addressFamily == AddressFamily.InterNetwork && bitCount > 32)
            throw new ArgumentOutOfRangeException(nameof(bitCount));
        if (addressFamily == AddressFamily.InterNetworkV6 && bitCount > 128)
            throw new ArgumentOutOfRangeException(nameof(bitCount));
        Span<byte> netmaskBytes = stackalloc byte[addressFamily == AddressFamily.InterNetwork ? 4 : 16];
        for (var x = 0; x < netmaskBytes.Length && bitCount > 0; x++)
        {
            var currentBits = bitCount > 8 ? 8 : bitCount;
            bitCount -= currentBits;
            var currentValue = (byte)(byte.MaxValue << (8 - currentBits));
            netmaskBytes[x] = currentValue;
        }

        return new IPAddress(netmaskBytes);
    }

    public static bool IsInNetwork(this IPAddress address, IPAddress network, int classlessInterDomainRoutingValue)
        => address.IsInNetwork(network,
            classlessInterDomainRoutingValue.ClasslessInterDomainRoutingToNetworkMask(network.AddressFamily));

    public static bool IsInNetwork(this IPAddress address, IPAddress network, IPAddress netmask)
    {
        if (address.AddressFamily != network.AddressFamily) return false;
        var maskedNetwork = network.GetNetwork(netmask);
        var maskedAddress = address.GetNetwork(netmask);
        return maskedAddress.Equals(maskedNetwork);
    }

    public static bool TryGetDnsEndPoint(
        this string str,
        int defaultPort,
        [NotNullWhen(true)] out DnsEndPoint? endPoint
    )
    {
        endPoint = null;
        var match = DomainNameValidationExtensions.GetDnsRegularExpression().Match(str);
        if (!match.Success) return false;
        var port = defaultPort;
        if (match.Groups["port"].Success)
            port = int.Parse(match.Groups["port"].ValueSpan);

        endPoint = new DnsEndPoint(match.Groups["name"].Value, port);
        return true;
    }

    public static EndPoint GetEndPoint(this string str, int defaultPort)
    {
        if (!str.TryGetEndPoint(defaultPort, out var endPoint))
            throw new ArgumentException("Value is not a valid IP or DNS value", nameof(str));

        return endPoint;
    }

    public static bool TryGetEndPoint(this string str, int defaultPort, [NotNullWhen(true)] out EndPoint? endPoint)
    {
        if (str.TryGetIPEndPoint(defaultPort, out var ipEndPoint))
        {
            endPoint = ipEndPoint;
            return true;
        }

        if (str.TryGetDnsEndPoint(defaultPort, out var dnsEndPoint))
        {
            endPoint = dnsEndPoint;
            return true;
        }

        endPoint = null;
        return false;
    }

    public static IPEndPoint GetIPEndPoint(this string address, int defaultPort)
    {
        if (!address.TryGetIPEndPoint(defaultPort, out var endPoint))
            throw new InvalidOperationException("String is not a valid address or endpoint!");

        return endPoint;
    }

    public static bool TryGetIPEndPoint(this string addressOrEndPoint, int defaultPort,
        [NotNullWhen(true)] out IPEndPoint? endPoint)
    {
        endPoint = null;

        if (IPAddress.TryParse(addressOrEndPoint, out var ipAddress))
        {
            endPoint = new IPEndPoint(ipAddress, defaultPort);
            return true;
        }

        if (IPEndPoint.TryParse(addressOrEndPoint, out endPoint))
            return true;

        return false;
    }

    public static bool IsValidMulticastAddress(this string address)
    {
        return address.TryGetIPEndPoint(123, out var endPoint) &&
               endPoint.Address.IsValidMulticastAddress();
    }

    public static bool IsValidIPAddress(this string address)
        => address.TryGetIPEndPoint(1, out _);

    public static bool IsValidMulticastAddress(this IPAddress address)
    {
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var firstOctet = address.GetAddressBytes()[0];
            return firstOctet is >= 224 and <= 239;
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            var firstOctet = address.GetAddressBytes()[0];
            return firstOctet == 255;
        }

        return false;
    }

    public static int ToNetworkByteOrder(this int i) => IPAddress.HostToNetworkOrder(i);
    public static int ToHostByteOrder(this int i) => IPAddress.NetworkToHostOrder(i);

    public static ushort ToNetworkByteOrder(this ushort i) => (ushort)IPAddress.HostToNetworkOrder((short)i);
    public static ushort ToHostByteOrder(this ushort i) => (ushort)IPAddress.NetworkToHostOrder((short)i);

    public static uint ToHostByteOrder(this uint u) => (uint)IPAddress.NetworkToHostOrder((int)u);
    public static uint ToNetworkByteOrder(this uint u) => (uint)IPAddress.HostToNetworkOrder((int)u);
}