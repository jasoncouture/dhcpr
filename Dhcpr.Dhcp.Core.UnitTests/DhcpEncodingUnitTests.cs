using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;

using Dhcpr.Dhcp.Core.Protocol;

namespace Dhcpr.Dhcp.Core.UnitTests;

[SuppressMessage("ReSharper", "ClassCanBeSealed.Global")]
public class DhcpEncodingUnitTests
{
    private static DhcpMessage TestMessage { get; } = DhcpMessage.Template with
    {
        HardwareAddress =
        new HardwareAddress(
            Enumerable.Range(0, 16).Select(i => (byte)i).ToImmutableArray(),
            HardwareAddressType.Ethernet,
            6
        ),
        Options = new DhcpOptionCollection
        (
            new[] { DhcpOption.Pad, DhcpOption.RapidCommit, DhcpOption.End }
        )
    };

    [Fact]
    public void DhcpMessageCanDecodeItsOwnEncodedMessage()
    {
        Span<byte> testMessageBytes = stackalloc byte[TestMessage.Size];
        Span<byte> reencodedMessageBytes = stackalloc byte[TestMessage.Size];
        TestMessage.EncodeTo(testMessageBytes);
        Assert.True(DhcpMessage.TryParse(testMessageBytes, out var decodedMessage));
        Assert.NotNull(decodedMessage);
        Assert.Equivalent(TestMessage.Options, decodedMessage.Options);
        decodedMessage.EncodeTo(reencodedMessageBytes);
        Assert.True(
            testMessageBytes.SequenceEqual(reencodedMessageBytes),
            "testMessageBytes.SequenceEqual(reencodedMessageBytes)"
        );
    }

    [Fact]
    public void EncodedMessageBytesMatchDecodedMessageBytes()
    {
        var testMessage = TestMessage;
        Span<byte> expectedMessageEncodedBytes = stackalloc byte[testMessage.Size];
        Span<byte> actualMessageEncodedBytes = stackalloc byte[testMessage.Size];

        testMessage.EncodeTo(expectedMessageEncodedBytes);
        Assert.True(DhcpMessage.TryParse(expectedMessageEncodedBytes, out var decodedMessage));
        Assert.NotNull(decodedMessage);
        Assert.Equal(testMessage.Size, decodedMessage.Size);
        decodedMessage.EncodeTo(actualMessageEncodedBytes);

        Assert.True(expectedMessageEncodedBytes.SequenceEqual(actualMessageEncodedBytes),
            "expectedMessageEncodedBytes.SequenceEqual(actualMessageEncodedBytes)");
    }
}