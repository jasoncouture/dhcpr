using Dhcpr.Dns.Core;

namespace Dhcpr.Dns.Core.UnitTests;

public class DnsHealthCheckConfigurationTests
{
    [Fact]
    public void TryValidate_Default_Succeeds()
    {
        var config = new DnsHealthCheckConfiguration();
        Assert.True(config.TryValidate(out var error));
        Assert.Null(error);
    }

    [Fact]
    public void TryValidate_InvalidTimeout_Fails()
    {
        var config = new DnsHealthCheckConfiguration { TimeoutSeconds = 0 };
        Assert.False(config.TryValidate(out var error));
        Assert.Contains("TimeoutSeconds", error);
    }

    [Fact]
    public void TryValidate_EmptyDomainEntry_Fails()
    {
        var config = new DnsHealthCheckConfiguration { Domains = ["example.com", "  "] };
        Assert.False(config.TryValidate(out var error));
        Assert.Contains("empty", error);
    }

    [Fact]
    public void TryValidate_InvalidDomain_Fails()
    {
        var config = new DnsHealthCheckConfiguration { Domains = ["not a domain"] };
        Assert.False(config.TryValidate(out var error));
        Assert.Contains("invalid domain", error);
    }

    [Fact]
    public void TryValidate_ValidDomains_Succeeds()
    {
        var config = new DnsHealthCheckConfiguration
        {
            Domains = ["example.com", "www.cloudflare.com."]
        };
        Assert.True(config.TryValidate(out _));
    }

    [Fact]
    public void DnsConfiguration_TryValidate_IncludesHealthCheck()
    {
        var dns = new DnsConfiguration
        {
            ListenAddresses = ["udp://127.0.0.1:53"],
            HealthCheck = new DnsHealthCheckConfiguration { TimeoutSeconds = 999 }
        };
        Assert.False(dns.TryValidate(out var error));
        Assert.Contains("HealthCheck", error);
    }
}
