namespace Dhcpr.Dns.Core;

public sealed class DnsOverHttpConfiguration
{
    /// <summary>Maximum accepted DNS wire payload (POST body or GET-decoded) in bytes.</summary>
    public int MaxRequestBytes { get; set; } = 65535;

    /// <summary>
    /// When true, the advertised DoH hostname answers only <c>/dns-query</c>
    /// (other paths 404). Set false to serve the operator UI on the same name.
    /// </summary>
    public bool IsolateHost { get; set; } = true;

    public bool Validate() => MaxRequestBytes is > 0 and <= 65535;
}
