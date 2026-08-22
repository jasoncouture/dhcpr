using Dhcpr.Dns.Core;

using Microsoft.Extensions.Options;

namespace Dhcpr.Server.Settings;

public static class RuntimeSettingsServiceCollectionExtensions
{
    public static IServiceCollection AddDhcprRuntimeSettings(this IServiceCollection services)
    {
        services.AddSingleton<RuntimeSettingsStore>();
        services.AddSingleton<IRuntimeSettingsStore>(static sp => sp.GetRequiredService<RuntimeSettingsStore>());
        services.AddHostedService<RuntimeSettingsWatchService>();
        services.AddSingleton<IPostConfigureOptions<DnsConfiguration>, RuntimeDnsSettingsPostConfigure>();
        services.AddSingleton<IPostConfigureOptions<DynamicDnsConfiguration>, RuntimeDynamicDnsSettingsPostConfigure>();
        services.AddSingleton<IOptionsChangeTokenSource<DnsConfiguration>,
            RuntimeSettingsChangeTokenSource<DnsConfiguration>>();
        services.AddSingleton<IOptionsChangeTokenSource<DynamicDnsConfiguration>,
            RuntimeSettingsChangeTokenSource<DynamicDnsConfiguration>>();
        return services;
    }
}
