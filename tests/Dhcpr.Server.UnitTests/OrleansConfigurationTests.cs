namespace Dhcpr.Server.UnitTests;

public class OrleansConfigurationTests
{
    [Fact]
    public void DisabledDefaultSucceeds()
    {
        var config = new OrleansConfiguration();
        Assert.False(config.UseConsul);
        Assert.True(config.TryValidate(out var error));
        Assert.Null(error);
    }

    [Fact]
    public void ConsulWithoutAddressFails()
    {
        var config = new OrleansConfiguration { UseConsul = true };
        Assert.False(config.TryValidate(out var error));
        Assert.Contains("Address", error);
    }

    [Fact]
    public void ConsulWithHttpAddressSucceeds()
    {
        var config = Consul("http://consul:8500");
        Assert.True(config.TryValidate(out var error));
        Assert.Null(error);
    }

    [Fact]
    public void ConsulRejectsNonHttpAddress()
    {
        var config = Consul("consul:8500");
        Assert.False(config.TryValidate(out var error));
        Assert.Contains("Address", error);
    }

    [Fact]
    public void ConsulRejectsInvalidAdvertisedIP()
    {
        var config = Consul("http://127.0.0.1:8500");
        config.AdvertisedIP = "not-an-ip";
        Assert.False(config.TryValidate(out var error));
        Assert.Contains("AdvertisedIP", error);
    }

    [Fact]
    public void ConsulAcceptsAdvertisedIP()
    {
        var config = Consul("http://127.0.0.1:8500");
        config.AdvertisedIP = "10.0.0.8";
        Assert.True(config.TryValidate(out var error));
        Assert.Null(error);
    }

    [Fact]
    public void ConsulRejectsInvalidSiloPort()
    {
        var config = Consul("http://127.0.0.1:8500");
        config.SiloPort = 0;
        Assert.False(config.TryValidate(out var error));
        Assert.Contains("SiloPort", error);
    }

    private static OrleansConfiguration Consul(string address) => new()
    {
        UseConsul = true,
        Consul = new ConsulClusteringConfiguration { Address = address }
    };
}
