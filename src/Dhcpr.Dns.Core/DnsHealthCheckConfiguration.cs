using System.Diagnostics.CodeAnalysis;

using Dhcpr.Core;

namespace Dhcpr.Dns.Core;

/// <summary>
/// Domains resolved on each ASP.NET health check. Any failure fails the check.
/// Bound under <c>DNS:HealthCheck</c>.
/// </summary>
public sealed class DnsHealthCheckConfiguration : IValidateSelf
{
    /// <summary>When false, the check is registered but always returns Healthy.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>Hostnames to resolve (A). Empty list → Healthy when enabled.</summary>
    public string[] Domains { get; set; } = [];

    /// <summary>Overall timeout for resolving all domains.</summary>
    public int TimeoutSeconds { get; set; } = 5;

    public bool Validate() => TryValidate(out _);

    public bool TryValidate([NotNullWhen(false)] out string? error)
    {
        Domains ??= [];

        if (TimeoutSeconds is < 1 or > 120)
        {
            error = "DNS:HealthCheck:TimeoutSeconds must be between 1 and 120";
            return false;
        }

        foreach (var domain in Domains)
        {
            if (string.IsNullOrWhiteSpace(domain))
            {
                error = "DNS:HealthCheck:Domains must not contain empty entries";
                return false;
            }

            if (!domain.Trim().TrimEnd('.').IsValidDomainName())
            {
                error = $"DNS:HealthCheck:Domains contains an invalid domain: {domain}";
                return false;
            }
        }

        error = null;
        return true;
    }
}
