using Dhcpr.Dns.Core;

using Microsoft.Extensions.Options;

namespace Dhcpr.Server.Settings;

internal sealed class RuntimeDnsSettingsPostConfigure(IRuntimeSettingsStore store)
    : IPostConfigureOptions<DnsConfiguration>
{
    public void PostConfigure(string? name, DnsConfiguration options)
    {
        var snapshot = store.Current;
        options.Routes = snapshot.Routes;
        options.Records = snapshot.Records;
        options.BlackholeDomains = snapshot.BlackholeDomains;
        options.Dnssec = snapshot.Dnssec;
        options.HealthCheck = snapshot.HealthCheck;
    }
}