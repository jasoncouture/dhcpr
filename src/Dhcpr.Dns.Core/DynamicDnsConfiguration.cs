using System.Diagnostics.CodeAnalysis;

namespace Dhcpr.Dns.Core;

public sealed class DynamicDnsConfiguration
{
    public bool Enabled { get; set; } = true;
    public string Username { get; set; } = "";
    public string Password { get; set; } = "";
    public int TtlSeconds { get; set; } = 60;
    public bool TrustForwardedFor { get; set; }

    [SuppressMessage("ReSharper", "ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract",
        Justification = "Values are set by configuration binding")]
    public bool Validate(out string? error)
    {
        error = null;
        if (!Enabled)
            return true;

        if (string.IsNullOrWhiteSpace(Username) || string.IsNullOrWhiteSpace(Password))
        {
            error = "DynamicDns:Username and DynamicDns:Password are required when DynamicDns is enabled";
            return false;
        }

        if (TtlSeconds is < 1 or > 86400)
        {
            error = "DynamicDns:TtlSeconds must be between 1 and 86400";
            return false;
        }

        return true;
    }
}
