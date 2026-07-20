using Dhcpr.Dns.Core;

namespace Dhcpr.Dns.Core.UnitTests;

public class DnsListenAddressTests
{
    [Theory]
    [InlineData("udp://127.0.0.1:53", DnsListenProtocol.Udp, "127.0.0.1", 53, false)]
    [InlineData("tcp://127.0.0.1:5353", DnsListenProtocol.Tcp, "127.0.0.1", 5353, false)]
    [InlineData("udp://[::1]:53", DnsListenProtocol.Udp, "::1", 53, false)]
    [InlineData("tcp://localhost:53", DnsListenProtocol.Tcp, "localhost", 53, false)]
    [InlineData("UDP://Example.COM:5353", DnsListenProtocol.Udp, "example.com", 5353, false)]
    [InlineData("udp://127.0.0.1", DnsListenProtocol.Udp, "127.0.0.1", 53, false)]
    [InlineData("interface://enp2s0:53/", DnsListenProtocol.Both, "enp2s0", 53, true)]
    [InlineData("interface://eth0:5353", DnsListenProtocol.Both, "eth0", 5353, true)]
    public void ParsesValidListenUris(
        string value,
        DnsListenProtocol protocol,
        string host,
        int port,
        bool isNetworkInterface)
    {
        Assert.True(DnsExtensions.TryParseListenAddress(value, out var endpoint));
        Assert.Equal(protocol, endpoint.Protocol);
        Assert.Equal(host, endpoint.Host);
        Assert.Equal(port, endpoint.Port);
        Assert.Equal(isNetworkInterface, endpoint.IsNetworkInterface);
    }

    [Theory]
    [InlineData("")]
    [InlineData("127.0.0.1:53")]
    [InlineData("http://127.0.0.1:53")]
    [InlineData("udp://")]
    [InlineData("interface://")]
    public void RejectsInvalidListenUris(string value)
    {
        Assert.False(DnsExtensions.TryParseListenAddress(value, out _));
    }

    [Fact]
    public void GetNetworkInterfaceNamesReturnsLocalInterfaces()
    {
        var names = DnsExtensions.GetNetworkInterfaceNames();
        Assert.NotEmpty(names);
    }
}
