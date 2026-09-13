using Dhcpr.Dns.Core;

namespace Dhcpr.Dns.Core.UnitTests;

public class UdpRateLimitConfigurationTests
{
    [Fact]
    public void DefaultsAreValid()
    {
        Assert.True(new UdpRateLimitConfiguration().TryValidate(out var error));
        Assert.Null(error);
    }

    [Fact]
    public void DropLimitMustExceedRefuseLimit()
    {
        var config = new UdpRateLimitConfiguration { RefuseLimit = 10, DropLimit = 10 };
        Assert.False(config.TryValidate(out var error));
        Assert.Contains("DropLimit", error, StringComparison.Ordinal);
    }
}
