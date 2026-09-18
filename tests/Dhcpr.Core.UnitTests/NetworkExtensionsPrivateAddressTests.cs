using System.Net;

using Dhcpr.Core;

namespace Dhcpr.Core.UnitTests;

public sealed class NetworkExtensionsPrivateAddressTests
{
    [Theory]
    [InlineData("10.0.0.0")]
    [InlineData("10.255.255.255")]
    [InlineData("172.16.0.0")]
    [InlineData("172.31.255.255")]
    [InlineData("192.168.0.0")]
    [InlineData("192.168.255.255")]
    [InlineData("169.254.0.0")]
    [InlineData("169.254.255.255")]
    [InlineData("fc00::")]
    [InlineData("fd12:3456:789a::1")]
    [InlineData("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")]
    [InlineData("fe80::")]
    [InlineData("fe80::1")]
    [InlineData("febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff")]
    [InlineData("::ffff:10.1.2.3")]
    [InlineData("::ffff:192.168.1.1")]
    [InlineData("::ffff:169.254.1.1")]
    public void PrivateCidrsArePrivate(string address)
        => Assert.True(IPAddress.Parse(address).IsPrivateAddress());

    [Theory]
    [InlineData("9.255.255.255")]
    [InlineData("11.0.0.0")]
    [InlineData("172.15.255.255")]
    [InlineData("172.32.0.0")]
    [InlineData("192.167.255.255")]
    [InlineData("192.169.0.0")]
    [InlineData("203.0.113.10")]
    [InlineData("127.0.0.1")]
    [InlineData("169.253.255.255")]
    [InlineData("169.255.0.0")]
    [InlineData("100.64.0.1")]
    [InlineData("::1")]
    [InlineData("2001:db8::1")]
    [InlineData("fe7f:ffff:ffff:ffff:ffff:ffff:ffff:ffff")]
    [InlineData("fec0::1")]
    [InlineData("::ffff:203.0.113.10")]
    public void PublicAndOtherReservedAreNotPrivate(string address)
        => Assert.False(IPAddress.Parse(address).IsPrivateAddress());
}
