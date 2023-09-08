using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Sockets;

namespace Dhcpr.Core;

public static class NetworkExtensions
{
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

    public static IPAddress ClasslessInterDomainRoutingToNetworkMask(this int bitCount, AddressFamily addressFamily)
    {
        if (addressFamily != AddressFamily.InterNetwork && addressFamily != AddressFamily.InterNetworkV6)
            throw new InvalidOperationException("Only IPv4 and IPv6 are supported.");
        Span<byte> netmaskBytes = stackalloc byte[addressFamily == AddressFamily.InterNetwork ? 4 : 16];
        for (var x = 0; x < netmaskBytes.Length && bitCount > 0; x++)
        {
            var currentBits = bitCount > 8 ? 8 : bitCount;
            bitCount -= currentBits;
            var currentValue = (byte)(byte.MaxValue << 8 - currentBits);
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

    public static IPEndPoint GetEndpoint(this string address, int defaultPort)
    {
        if (!address.TryGetEndpoint(defaultPort, out var endPoint))
            throw new InvalidOperationException("String is not a valid address or endpoint!");

        return endPoint;
    }

    public static bool TryGetEndpoint(this string addressOrEndPoint, int defaultPort,
        [NotNullWhen(true)] out IPEndPoint? endPoint)
    {
        endPoint = null;
        if (IPEndPoint.TryParse(addressOrEndPoint, out endPoint))
            return true;

        if (IPAddress.TryParse(addressOrEndPoint, out var ipAddress))
        {
            endPoint = new IPEndPoint(ipAddress, defaultPort);
            return true;
        }

        return false;
    }

    public static bool IsValidMulticastAddress(this string address)
    {
        return address.TryGetEndpoint(123, out var endPoint) &&
               endPoint.Address.IsValidMulticastAddress();
    }

    public static bool IsValidIPAddress(this string address)
        => address.TryGetEndpoint(1, out _);

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
}