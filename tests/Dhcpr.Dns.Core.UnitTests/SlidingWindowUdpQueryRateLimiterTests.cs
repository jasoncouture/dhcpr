using System.Net;

using Dhcpr.Dns.Core;
using Dhcpr.Dns.Core.Protocol.Processing;

using Microsoft.Extensions.Options;

using NSubstitute;

namespace Dhcpr.Dns.Core.UnitTests;

public class SlidingWindowUdpQueryRateLimiterTests
{
    [Fact]
    public void AllowsThenRefusesThenDrops()
    {
        var limiter = Create(refuse: 2, drop: 4);
        var client = IPAddress.Parse("203.0.113.10");

        Assert.Equal(UdpRateLimitAction.Allow, limiter.Record(client));
        Assert.Equal(UdpRateLimitAction.Allow, limiter.Record(client));
        Assert.Equal(UdpRateLimitAction.Refuse, limiter.Record(client));
        Assert.Equal(UdpRateLimitAction.Refuse, limiter.Record(client));
        Assert.Equal(UdpRateLimitAction.Drop, limiter.Record(client));
    }

    [Fact]
    public void ExemptsLoopback()
    {
        var limiter = Create(refuse: 1, drop: 2);

        for (var i = 0; i < 8; i++)
            Assert.Equal(UdpRateLimitAction.Allow, limiter.Record(IPAddress.Loopback));
    }

    [Fact]
    public void GroupsIpv6BySlash64()
    {
        var limiter = Create(refuse: 1, drop: 3);
        var a = IPAddress.Parse("2001:db8:1:2::1");
        var b = IPAddress.Parse("2001:db8:1:2::99");
        var other = IPAddress.Parse("2001:db8:1:3::1");

        Assert.Equal(UdpRateLimitAction.Allow, limiter.Record(a));
        Assert.Equal(UdpRateLimitAction.Refuse, limiter.Record(b));
        Assert.Equal(UdpRateLimitAction.Allow, limiter.Record(other));
    }

    [Fact]
    public void DisabledAllowsEveryone()
    {
        var limiter = Create(refuse: 1, drop: 2, enabled: false);
        var client = IPAddress.Parse("203.0.113.10");

        for (var i = 0; i < 8; i++)
            Assert.Equal(UdpRateLimitAction.Allow, limiter.Record(client));
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
