using System.Net;

using Dhcpr.Dns.Core;
using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;

using Microsoft.Extensions.Options;

using NSubstitute;

namespace Dhcpr.Dns.Core.UnitTests;

public class SlidingWindowUdpQueryRateLimiterTests
{
    private static readonly DomainLabels Cisco = new("cisco.com");
    private static readonly DomainLabels Example = new("example.com");

    [Fact]
    public void AllowsThenRefusesThenDrops()
    {
        var limiter = Create(refuse: 2, drop: 4);
        var client = IPAddress.Parse("203.0.113.10");

        Assert.Equal(UdpRateLimitAction.Allow, limiter.Record(client, Cisco, DomainRecordType.TXT));
        Assert.Equal(UdpRateLimitAction.Allow, limiter.Record(client, Cisco, DomainRecordType.TXT));
        Assert.Equal(UdpRateLimitAction.Refuse, limiter.Record(client, Cisco, DomainRecordType.TXT));
        Assert.Equal(UdpRateLimitAction.Refuse, limiter.Record(client, Cisco, DomainRecordType.TXT));
        Assert.Equal(UdpRateLimitAction.Drop, limiter.Record(client, Cisco, DomainRecordType.TXT));
    }

    [Fact]
    public void DifferentNamesHaveIndependentWindows()
    {
        var limiter = Create(refuse: 1, drop: 3);
        var client = IPAddress.Parse("203.0.113.10");

        Assert.Equal(UdpRateLimitAction.Allow, limiter.Record(client, Cisco, DomainRecordType.TXT));
        Assert.Equal(UdpRateLimitAction.Refuse, limiter.Record(client, Cisco, DomainRecordType.TXT));
        Assert.Equal(UdpRateLimitAction.Allow, limiter.Record(client, Example, DomainRecordType.TXT));
    }

    [Fact]
    public void DifferentTypesHaveIndependentWindows()
    {
        var limiter = Create(refuse: 1, drop: 3);
        var client = IPAddress.Parse("203.0.113.10");

        Assert.Equal(UdpRateLimitAction.Allow, limiter.Record(client, Cisco, DomainRecordType.TXT));
        Assert.Equal(UdpRateLimitAction.Refuse, limiter.Record(client, Cisco, DomainRecordType.TXT));
        Assert.Equal(UdpRateLimitAction.Allow, limiter.Record(client, Cisco, DomainRecordType.A));
    }

    [Fact]
    public void NameKeyIsCaseInsensitive()
    {
        var limiter = Create(refuse: 1, drop: 3);
        var client = IPAddress.Parse("203.0.113.10");

        Assert.Equal(UdpRateLimitAction.Allow, limiter.Record(client, new DomainLabels("Cisco.COM"), DomainRecordType.TXT));
        Assert.Equal(UdpRateLimitAction.Refuse, limiter.Record(client, new DomainLabels("cisco.com"), DomainRecordType.TXT));
    }

    [Fact]
    public void ExemptsLoopback()
    {
        var limiter = Create(refuse: 1, drop: 2);

        for (var i = 0; i < 8; i++)
            Assert.Equal(UdpRateLimitAction.Allow, limiter.Record(IPAddress.Loopback, Cisco, DomainRecordType.TXT));
    }

    [Theory]
    [InlineData("10.1.2.3")]
    [InlineData("172.16.0.1")]
    [InlineData("192.168.1.50")]
    [InlineData("fd12:3456:789a::1")]
    [InlineData("fc00::1")]
    [InlineData("::ffff:10.0.0.8")]
    public void ExemptsPrivateAddresses(string address)
    {
        var limiter = Create(refuse: 1, drop: 2);
        var client = IPAddress.Parse(address);

        for (var i = 0; i < 8; i++)
            Assert.Equal(UdpRateLimitAction.Allow, limiter.Record(client, Cisco, DomainRecordType.TXT));
    }

    [Fact]
    public void GroupsIpv6BySlash64()
    {
        var limiter = Create(refuse: 1, drop: 3);
        var a = IPAddress.Parse("2001:db8:1:2::1");
        var b = IPAddress.Parse("2001:db8:1:2::99");
        var other = IPAddress.Parse("2001:db8:1:3::1");

        Assert.Equal(UdpRateLimitAction.Allow, limiter.Record(a, Cisco, DomainRecordType.TXT));
        Assert.Equal(UdpRateLimitAction.Refuse, limiter.Record(b, Cisco, DomainRecordType.TXT));
        Assert.Equal(UdpRateLimitAction.Allow, limiter.Record(other, Cisco, DomainRecordType.TXT));
    }

    [Fact]
    public void IpWindowDropsAtRefuseRateOverLongerWindow()
    {
        var limiter = Create(refuse: 1, drop: 3);
        var client = IPAddress.Parse("203.0.113.10");

        // Budget is RefuseLimit × 5s = 5. Count < 5 is allowed; at 5 (1/s over 5s) drop.
        for (var i = 0; i < SlidingWindowUdpQueryRateLimiter.IpLimitMultiplier - 1; i++)
        {
            var name = new DomainLabels($"n{i}.example");
            Assert.Equal(UdpRateLimitAction.Allow, limiter.Record(client, name, DomainRecordType.A));
        }

        Assert.Equal(
            UdpRateLimitAction.Drop,
            limiter.Record(client, new DomainLabels("overflow.example"), DomainRecordType.A));
    }

    [Fact]
    public void DisabledAllowsEveryone()
    {
        var limiter = Create(refuse: 1, drop: 2, enabled: false);
        var client = IPAddress.Parse("203.0.113.10");

        for (var i = 0; i < 8; i++)
            Assert.Equal(UdpRateLimitAction.Allow, limiter.Record(client, Cisco, DomainRecordType.TXT));
    }

    private static SlidingWindowUdpQueryRateLimiter Create(int refuse, int drop, bool enabled = true)
    {
        var monitor = Substitute.For<IOptionsMonitor<DnsConfiguration>>();
        monitor.CurrentValue.Returns(new DnsConfiguration
        {
            ListenAddresses = ["udp://127.0.0.1:53"],
            UdpRateLimit = new UdpRateLimitConfiguration
            {
                Enabled = enabled,
                RefuseLimit = refuse,
                DropLimit = drop,
                WindowMilliseconds = 1000,
                SegmentsPerWindow = 10
            }
        });
        return new SlidingWindowUdpQueryRateLimiter(monitor);
    }
}
