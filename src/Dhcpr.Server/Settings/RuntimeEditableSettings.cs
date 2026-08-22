using Dhcpr.Dns.Core;

namespace Dhcpr.Server.Settings;

public sealed class RuntimeEditableSettings
{
    public Dictionary<string, DnsRouteConfiguration> Routes { get; set; } =
        new(StringComparer.OrdinalIgnoreCase);

    public DnsRecordConfiguration[] Records { get; set; } = [];

    public string[] BlackholeDomains { get; set; } = [];
    public DnssecConfiguration Dnssec { get; set; } = new();
    public DnsHealthCheckConfiguration HealthCheck { get; set; } = new();
    public DynamicDnsConfiguration DynamicDns { get; set; } = new();

    public RuntimeEditableSettings Clone()
        => new()
        {
            Routes = Routes.ToDictionary(
                static kv => kv.Key,
                static kv => new DnsRouteConfiguration
                {
                    Upstreams = [.. kv.Value.Upstreams ?? []],
                    Clients = [.. kv.Value.Clients ?? []]
                },
                StringComparer.OrdinalIgnoreCase),
            Records = (Records ?? []).Select(static r => new DnsRecordConfiguration
            {
                Name = r.Name,
                Type = r.Type,
                Ttl = r.Ttl,
                Value = r.Value,
                Clients = [.. r.Clients ?? []]
            }).ToArray(),
            BlackholeDomains = [.. BlackholeDomains],
            Dnssec = new DnssecConfiguration
            {
                Enabled = Dnssec.Enabled,
                AllowedAlgorithms = [.. Dnssec.AllowedAlgorithms ?? []],
                DeniedAlgorithms = [.. Dnssec.DeniedAlgorithms ?? []]
            },
            HealthCheck = new DnsHealthCheckConfiguration
            {
                Enabled = HealthCheck.Enabled,
                Domains = [.. HealthCheck.Domains ?? []],
                TimeoutSeconds = HealthCheck.TimeoutSeconds
            },
            DynamicDns = new DynamicDnsConfiguration
            {
                Enabled = DynamicDns.Enabled,
                Username = DynamicDns.Username,
                Password = DynamicDns.Password,
                TtlSeconds = DynamicDns.TtlSeconds,
                TrustForwardedFor = DynamicDns.TrustForwardedFor
            }
        };
}
