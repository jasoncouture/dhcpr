namespace Dhcpr.Server.UnitTests;

public class AuthenticationConfigurationTests
{
    [Fact]
    public void DisabledDefaultSucceeds()
    {
        var config = new AuthenticationConfiguration();
        Assert.False(config.Enabled);
        Assert.True(config.TryValidate(out var error));
        Assert.Null(error);
    }

    [Fact]
    public void DisabledIgnoresMissingKeycloak()
    {
        var config = new AuthenticationConfiguration
        {
            Enabled = false,
            Keycloak = new KeycloakAuthenticationConfiguration()
        };
        Assert.True(config.TryValidate(out var error));
        Assert.Null(error);
    }

    [Fact]
    public void EnabledWithoutAuthorityFails()
    {
        var config = Enabled();
        config.Keycloak.Authority = "";
        Assert.False(config.TryValidate(out var error));
        Assert.Contains("Authority", error);
    }

    [Fact]
    public void EnabledWithoutClientIdFails()
    {
        var config = Enabled();
        config.Keycloak.ClientId = "";
        Assert.False(config.TryValidate(out var error));
        Assert.Contains("ClientId", error);
    }

    [Fact]
    public void EnabledWithAuthorityAndClientIdSucceeds()
    {
        var config = Enabled();
        Assert.True(config.TryValidate(out var error));
        Assert.Null(error);
    }

    private static AuthenticationConfiguration Enabled() => new()
    {
        Enabled = true,
        Keycloak = new KeycloakAuthenticationConfiguration
        {
            Authority = "https://auth.example/realms/master",
            ClientId = "dhcpr"
        }
    };
}
