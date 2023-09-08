using System.Collections.Immutable;
using System.Net;

using Dhcpr.Dhcp.Core.Protocol;

namespace Dhcpr.Dhcp.Core.UnitTests;

public class DhcpEncodingUnitTests
{
    [Fact]
    public void DhcpMessageCanDecodeItsOwnEncodedMessage()
    {
        var testMessage = new DhcpMessage(BootOperationCode.Request, HardwareAddressType.Ethernet, 6, 0, 1234, 1,
            DhcpFlags.Broadcast, IPAddress.Any, IPAddress.Any, IPAddress.Any, IPAddress.Any,
            new HardwareAddress(Enumerable.Range(0, 16).Select(i => (byte)i).ToImmutableArray(), 6), "abcd", "efg",
            new DhcpOptionCollection(ImmutableArray<DhcpOption>.Empty));

        Span<byte> testMessageBytes = stackalloc byte[testMessage.Size];
        testMessage.EncodeTo(testMessageBytes);
        Assert.True(DhcpMessage.TryParse(testMessageBytes, out var decodedMessage));
        Assert.NotNull(decodedMessage);
        Assert.Equal(testMessage.HardwareAddressType, decodedMessage.HardwareAddressType);
    }
}