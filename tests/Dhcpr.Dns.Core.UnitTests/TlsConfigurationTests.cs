using System.Net;

using Dhcpr.Dns.Core;

namespace Dhcpr.Dns.Core.UnitTests;

public class TlsConfigurationTests
{
    [Fact]
    public void DisabledWithEmptyListenersSucceeds()
    {
        var config = new TlsConfiguration();
        Assert.True(config.TryValidate(out var error));
        Assert.Null(error);
        Assert.Empty(config.GetParsedListeners());
    }

    [Fact]
    public void DisabledIgnoresListenersAndCertPaths()
    {
        var config = new TlsConfiguration
        {
            Enabled = false,
            Listeners = ["not valid"],
            CertificatePath = "",
            PrivateKeyPath = ""
        };
        Assert.True(config.TryValidate(out var error));
        Assert.Null(error);
        Assert.Empty(config.GetParsedListeners());
    }

    [Fact]
    public void EnabledWithEmptyListenersFails()
    {
        var config = EnabledWithCerts();
        config.Listeners = [];
        Assert.False(config.TryValidate(out var error));
        Assert.Contains("Listeners", error);
    }

    [Fact]
    public void EnabledWithInvalidListenerFails()
    {
        var config = EnabledWithCerts();
        config.Listeners = ["not a valid endpoint"];
        Assert.False(config.TryValidate(out var error));
        Assert.Contains("Listeners[0]", error);
    }

    [Fact]
    public void EnabledWithoutCertificatePathFails()
    {
        var config = EnabledWithCerts();
        config.CertificatePath = " ";
        Assert.False(config.TryValidate(out var error));
        Assert.Contains("CertificatePath", error);
    }

    [Fact]
    public void EnabledWithoutPrivateKeyPathFails()
    {
        var config = EnabledWithCerts();
        config.PrivateKeyPath = "";
        Assert.False(config.TryValidate(out var error));
        Assert.Contains("PrivateKeyPath", error);
    }

    [Theory]
    [InlineData("0.0.0.0:853", "0.0.0.0", 853)]
    [InlineData("[::]:853", "::", 853)]
    [InlineData("127.0.0.1", "127.0.0.1", 853)]
    [InlineData("::1", "::1", 853)]
    public void EnabledParsesIpListenersWithDefaultPort(string listener, string address, int port)
    {
        var config = EnabledWithCerts();
        config.Listeners = [listener];
        Assert.True(config.TryValidate(out var error));
        Assert.Null(error);
        var parsed = Assert.IsType<IPEndPoint>(Assert.Single(config.GetParsedListeners()));
        Assert.Equal(IPAddress.Parse(address), parsed.Address);
        Assert.Equal(port, parsed.Port);
    }

    private static TlsConfiguration EnabledWithCerts() => new()
    {
        Enabled = true,
        Listeners = ["127.0.0.1:853"],
        CertificatePath = "/tls/tls.crt",
        PrivateKeyPath = "/tls/tls.key"
    };
}
