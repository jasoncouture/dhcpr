using System.Net;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;

namespace Dhcpr.Dns.Core.UnitTests;

public class NameserverTipCacheTests
{
    [Fact]
    public void TryGetClosestPrefersLongestMatchingSuffix()
    {
        var com = new IPEndPoint(IPAddress.Parse("192.5.6.30"), 53);
        var netflix = new IPEndPoint(IPAddress.Parse("192.0.2.10"), 53);
        var cache = new NameserverTipCache();
        cache.Remember("com", [com]);
        cache.Remember("netflix.com", [netflix]);

        Assert.True(cache.TryGetClosest(
            new DomainLabels("ichnaea-web.dradis.netflix.com"),
            DomainRecordType.A,
            out var tips,
            out var zone));
        Assert.Equal("netflix.com", zone.ToString());
        Assert.Equal(new[] { netflix }, tips);

        Assert.True(cache.TryGetClosest(
            new DomainLabels("elb.us-east-2.amazonaws.com"),
            DomainRecordType.A,
            out tips,
            out zone));
        Assert.Equal("com", zone.ToString());
        Assert.Equal(new[] { com }, tips);
    }

    [Fact]
    public void DsDoesNotUseSelfTip()
    {
        var com = new IPEndPoint(IPAddress.Parse("192.5.6.30"), 53);
        var cache = new NameserverTipCache();
        cache.Remember("com", [com]);

        Assert.False(cache.TryGetClosest(
            new DomainLabels("com"),
            DomainRecordType.DS,
            out _,
            out _));

        Assert.True(cache.TryGetClosest(
            new DomainLabels("cloudflare.com"),
            DomainRecordType.DS,
            out var tips,
            out var zone));
        Assert.Equal("com", zone.ToString());
        Assert.Equal(new[] { com }, tips);
    }

    [Fact]
    public void TryGetClosestReturnsFalseWhenEmpty()
    {
        var cache = new NameserverTipCache();
        Assert.False(cache.TryGetClosest(
            new DomainLabels("example.com"), DomainRecordType.A, out _, out _));
    }
}
