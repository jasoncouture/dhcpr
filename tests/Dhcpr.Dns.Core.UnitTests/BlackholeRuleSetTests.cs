namespace Dhcpr.Dns.Core.UnitTests;

public sealed class BlackholeRuleSetTests
{
    [Theory]
    [InlineData("dhitc.com", false)]
    [InlineData("ads.example", false)]
    [InlineData(@".+\..+\.localdomain$", true)]
    [InlineData(@"/^.+\.evil$/", true)]
    [InlineData(@"/foo/", true)]
    [InlineData("^root", true)]
    [InlineData(@"foo\.bar", true)]
    public void ClassifiesSuffixVersusRegex(string entry, bool regex)
        => Assert.Equal(regex, BlackholeRuleSet.LooksLikeRegex(entry));

    [Fact]
    public void RejectsInvalidRegex()
    {
        Assert.False(BlackholeRuleSet.TryCreate(["(["], out var error, out _));
        Assert.Contains("valid regex", error);
    }

    [Theory]
    [InlineData("/foo")]
    [InlineData("/foo/i")]
    public void RejectsUnclosedSlashRegex(string entry)
    {
        Assert.False(BlackholeRuleSet.TryCreate([entry], out var error, out _));
        Assert.Contains("closing", error);
    }

    [Fact]
    public void AcceptsInlineNetOptions()
    {
        Assert.True(BlackholeRuleSet.TryCreate([@"(?i).+\..+\.localdomain$"], out var error, out var rules), error);
        Assert.True(rules.Matches("A.B.LOCALDOMAIN"));
    }

    [Fact]
    public void DnsConfigurationRejectsInvalidRegex()
    {
        var dns = new DnsConfiguration
        {
            ListenAddresses = ["udp://127.0.0.1:53"],
            BlackholeDomains = ["(["]
        };

        Assert.False(dns.TryValidate(out var error));
        Assert.Contains("valid regex", error);
    }

    [Fact]
    public void DnsConfigurationAcceptsLocaldomainRegex()
    {
        var dns = new DnsConfiguration
        {
            ListenAddresses = ["udp://127.0.0.1:53"],
            BlackholeDomains = [@".+\..+\.localdomain$", "dhitc.com"]
        };

        Assert.True(dns.TryValidate(out var error), error);
        var rules = dns.GetBlackholeRules();
        Assert.True(rules.Matches("a.b.localdomain"));
        Assert.False(rules.Matches("host.localdomain"));
        Assert.True(rules.Matches("www.dhitc.com"));
    }
}
