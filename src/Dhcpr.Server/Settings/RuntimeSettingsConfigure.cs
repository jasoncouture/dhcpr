using Dhcpr.Dns.Core;

using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;

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

internal sealed class RuntimeDynamicDnsSettingsPostConfigure(IRuntimeSettingsStore store)
    : IPostConfigureOptions<DynamicDnsConfiguration>
{
    public void PostConfigure(string? name, DynamicDnsConfiguration options)
    {
        var snapshot = store.Current.DynamicDns;
        options.Enabled = snapshot.Enabled;
        options.Username = snapshot.Username;
        options.Password = snapshot.Password;
        options.TtlSeconds = snapshot.TtlSeconds;
        options.TrustForwardedFor = snapshot.TrustForwardedFor;
    }
}

internal sealed class RuntimeSettingsChangeTokenSource<TOptions>(IRuntimeSettingsStore store)
    : IOptionsChangeTokenSource<TOptions>
{
    public string Name => Options.DefaultName;
    public IChangeToken GetChangeToken() => store.GetChangeToken();
}
