using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Resolvers.Caching;

namespace Dhcpr.Dns.Core.UnitTests;

public class UnreachableAuthorityCacheTests
{
    [Fact]
    public void RememberedCut_CoversChildNames_AndNotTheParent()
    {
        var cache = new UnreachableAuthorityCache();
        cache.Remember("netdimensional.top");

        Assert.True(cache.Contains(new DomainLabels("netdimensional.top")));
        Assert.True(cache.Contains(new DomainLabels("www.netdimensional.top")));
        Assert.False(cache.Contains(new DomainLabels("top")));
        Assert.False(cache.Contains(new DomainLabels("example.com")));
    }

    [Fact]
    public void Root_IsNotRemembered()
    {
        var cache = new UnreachableAuthorityCache();
        cache.Remember(".");
        Assert.False(cache.Contains(new DomainLabels("netdimensional.top")));
    }
}
