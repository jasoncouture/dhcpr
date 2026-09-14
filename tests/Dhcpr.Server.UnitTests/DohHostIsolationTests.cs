using Dhcpr.Dns.Core;

using Microsoft.AspNetCore.Http;

namespace Dhcpr.Server.UnitTests;

public class DohHostIsolationTests
{
    [Theory]
    [InlineData("/dns-query")]
    [InlineData("/dns-query/")]
    [InlineData("/DNS-QUERY")]
    public void DnsQueryPathIsAllowed(string path)
        => Assert.True(DohHostIsolation.IsDnsQueryPath(path));

    [Theory]
    [InlineData("/")]
    [InlineData("/orleans")]
    [InlineData("/dns-query/extra")]
    [InlineData("/nic/update")]
    public void OtherPathsAreNotDnsQuery(string path)
        => Assert.False(DohHostIsolation.IsDnsQueryPath(path));

    [Fact]
    public void HostMatchesIgnoresPortAndCaseAndTrailingDot()
    {
        var hosts = new[] { "dns.alertr.info" };
        Assert.True(DohHostIsolation.HostMatches(new HostString("dns.alertr.info:443"), hosts));
        Assert.True(DohHostIsolation.HostMatches(new HostString("DNS.ALERTR.INFO"), hosts));
        Assert.True(DohHostIsolation.HostMatches(new HostString("dns.alertr.info."), hosts));
        Assert.False(DohHostIsolation.HostMatches(new HostString("ui.alertr.info"), hosts));
        Assert.False(DohHostIsolation.HostMatches(new HostString(""), hosts));
    }

    [Fact]
    public void AdvertisedHostsPreferDesignatedResolvers()
    {
        var dns = new DnsConfiguration
        {
            ListenAddresses = ["udp://127.0.0.1:53"],
            DesignatedResolvers =
            [
                new DesignatedResolverConfiguration { Target = "dns.example.com" },
                new DesignatedResolverConfiguration { Target = "dns.example.com." }
            ]
        };
        var tls = new TlsConfiguration { Enabled = true };

        var hosts = DohHostIsolation.AdvertisedHosts(dns, tls, certificate: null);

        Assert.Equal(2, hosts.Count);
        Assert.All(hosts, static h => Assert.Equal("dns.example.com", h, StringComparer.OrdinalIgnoreCase));
    }

    [Fact]
    public void AdvertisedHostsEmptyWhenNothingConfigured()
    {
        var dns = new DnsConfiguration { ListenAddresses = ["udp://127.0.0.1:53"] };
        var tls = new TlsConfiguration();

        Assert.Empty(DohHostIsolation.AdvertisedHosts(dns, tls, certificate: null));
    }

    [Fact]
    public void ShouldReturnNotFoundOnAdvertisedHostForOtherPaths()
    {
        var dns = DohDns("dns.example.com");
        var tls = new TlsConfiguration { Enabled = true };

        Assert.True(DohHostIsolation.ShouldReturnNotFound(
            "/", new HostString("dns.example.com"), dns, tls, certificate: null));
        Assert.False(DohHostIsolation.ShouldReturnNotFound(
            "/dns-query", new HostString("dns.example.com"), dns, tls, certificate: null));
        Assert.False(DohHostIsolation.ShouldReturnNotFound(
            "/", new HostString("ui.example.com"), dns, tls, certificate: null));
    }

    [Fact]
    public void IsolateHostFalseNeverReturnsNotFound()
    {
        var dns = DohDns("dns.example.com");
        dns.DnsOverHttp.IsolateHost = false;
        var tls = new TlsConfiguration { Enabled = true };

        Assert.False(DohHostIsolation.ShouldReturnNotFound(
            "/", new HostString("dns.example.com"), dns, tls, certificate: null));
        Assert.False(DohHostIsolation.ShouldReturnNotFound(
            "/orleans", new HostString("dns.example.com"), dns, tls, certificate: null));
    }

    private static DnsConfiguration DohDns(string target)
        => new()
        {
            ListenAddresses = ["udp://127.0.0.1:53"],
            DesignatedResolvers = [new DesignatedResolverConfiguration { Target = target }]
        };
}
