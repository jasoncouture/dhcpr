using System.Buffers;
using System.Collections.Immutable;
using System.Net;
using System.Net.Sockets;

using Dhcpr.Core;
using Dhcpr.Core.Linq;

namespace Dhcpr.Dhcp.Core.Client;

public sealed record IPAddressRange(IPAddress StartAddress, IPAddress EndAddress)
{
    private IEnumerable<IPAddress>? _availableAddresses;

    private IEnumerable<IPAddress> SelectableAddresses =>
        _availableAddresses ??= ComputeAvailableAddresses(StartAddress, EndAddress).ToImmutableHashSet();

    private IEnumerable<IPAddress> ComputeAvailableAddresses(IPAddress startAddress, IPAddress endAddress)
    {
        if (startAddress.AddressFamily != AddressFamily.InterNetwork)
            throw new InvalidOperationException("Only IPv4 is supported");
        if (startAddress.AddressFamily != endAddress.AddressFamily)
            throw new InvalidOperationException("Only IPv4 is supported");

        var rangeStart = BitConverter.ToUInt32(StartAddress.GetAddressBytes()).ToHostByteOrder();
        var rangeEnd = BitConverter.ToUInt32(EndAddress.GetAddressBytes()).ToHostByteOrder();

        byte[] addressByteBuffer = ArrayPool<byte>.Shared.Rent(4);
        try
        {
            for (var x = rangeStart; x <= rangeEnd; x++)
            {
                BitConverter.TryWriteBytes(addressByteBuffer, x.ToNetworkByteOrder());
                yield return new IPAddress(addressByteBuffer[..4]);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(addressByteBuffer);
        }
    }

    public IPAddress? SelectAddress(IEnumerable<IPAddress> usedAddresses)
    {
        using var selectable = SelectableAddresses.Except(usedAddresses).ToPooledList();

        if (selectable.Count == 0) return null;
        var selectedIndex = Random.Shared.Next(0, selectable.Count);

        return selectable[selectedIndex];
    }
}