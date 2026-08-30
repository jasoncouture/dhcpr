namespace Dhcpr.Server;

public sealed class KeycloakAuthenticationConfiguration
{
    public string Authority { get; set; } = "";

    public string ClientId { get; set; } = "";
}
