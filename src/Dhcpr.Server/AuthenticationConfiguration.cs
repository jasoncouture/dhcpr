using System.Diagnostics.CodeAnalysis;

using Dhcpr.Core;

namespace Dhcpr.Server;

public sealed class AuthenticationConfiguration : IValidateSelf
{
    public bool Enabled { get; set; }

    public KeycloakAuthenticationConfiguration Keycloak { get; set; } = new();

    public bool Validate() => TryValidate(out _);

    [SuppressMessage("ReSharper", "ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract",
        Justification = "Values are set by configuration binding")]
    public bool TryValidate([NotNullWhen(false)] out string? error)
    {
        Keycloak ??= new KeycloakAuthenticationConfiguration();
        Keycloak.Authority ??= "";
        Keycloak.ClientId ??= "";

        if (!Enabled)
        {
            error = null;
            return true;
        }

        if (string.IsNullOrWhiteSpace(Keycloak.Authority))
        {
            error = "Authentication:Keycloak:Authority is required when Authentication is enabled";
            return false;
        }

        if (string.IsNullOrWhiteSpace(Keycloak.ClientId))
        {
            error = "Authentication:Keycloak:ClientId is required when Authentication is enabled";
            return false;
        }

        error = null;
        return true;
    }
}
