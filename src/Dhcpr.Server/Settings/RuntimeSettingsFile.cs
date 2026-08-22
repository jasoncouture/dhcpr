using Dhcpr.Dns.Core;

namespace Dhcpr.Server.Settings;

internal sealed class RuntimeSettingsFile
{
    public DnsRuntimeSettingsSection DNS { get; set; } = new();
    public DynamicDnsConfiguration DynamicDns { get; set; } = new();
}

internal sealed class DnsRuntimeSettingsSection
{
    public Dictionary<string, DnsRouteConfiguration> Routes { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public DnsRecordConfiguration[] Records { get; set; } = [];
    public string[] BlackholeDomains { get; set; } = [];
    public DnssecConfiguration Dnssec { get; set; } = new();
    public DnsHealthCheckConfiguration HealthCheck { get; set; } = new();
}
