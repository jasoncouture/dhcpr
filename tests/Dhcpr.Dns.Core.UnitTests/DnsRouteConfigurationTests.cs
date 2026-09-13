using Dhcpr.Dns.Core;

namespace Dhcpr.Dns.Core.UnitTests;

public class DnsRouteConfigurationTests
{
    [Theory]
    [InlineData(".", ".")]
    [InlineData(" . ", ".")]
    [InlineData("example.com", "example.com")]
    [InlineData("example.com.", "example.com")]
    [InlineData("HOME.ARPA.", "HOME.ARPA")]
    public void NormalizeSuffixKeepsRootDot(string input, string expected)
    {
        Assert.True(DnsRouteConfiguration.TryNormalizeSuffix(input, out var suffix));
        Assert.Equal(expected, suffix);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("...")]
    public void NormalizeSuffixRejectsEmpty(string? input)
        => Assert.False(DnsRouteConfiguration.TryNormalizeSuffix(input, out _));

    [Fact]
    public void RootRouteValidates()
    {
        var config = new DnsConfiguration
        {
            ListenAddresses = ["udp://127.0.0.1:53"],
            Routes = new Dictionary<string, DnsRouteConfiguration>
            {
                ["."] = new() { Upstreams = ["1.1.1.1"] }
            }
        };

        Assert.True(config.TryValidate(out var error), error);
        Assert.True(config.GetParsedRoutes().ContainsKey("."));
    }
}
