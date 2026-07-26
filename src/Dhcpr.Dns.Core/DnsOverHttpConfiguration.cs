namespace Dhcpr.Dns.Core;

public sealed class DnsOverHttpConfiguration
{
    /// <summary>Maximum accepted DNS wire payload (POST body or GET-decoded) in bytes.</summary>
    public int MaxRequestBytes { get; set; } = 65535;

    public bool Validate() => MaxRequestBytes is > 0 and <= 65535;
}
