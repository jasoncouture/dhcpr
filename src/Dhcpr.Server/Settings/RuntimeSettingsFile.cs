using Dhcpr.Dns.Core;

namespace Dhcpr.Server.Settings;

internal sealed class RuntimeSettingsFile
{
    public DnsRuntimeSettingsSection DNS { get; set; } = new();
    public DynamicDnsConfiguration DynamicDns { get; set; } = new();
}