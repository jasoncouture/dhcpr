using Dhcpr.Dns.Core;

using Microsoft.Extensions.Options;

namespace Dhcpr.Server.Settings;

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