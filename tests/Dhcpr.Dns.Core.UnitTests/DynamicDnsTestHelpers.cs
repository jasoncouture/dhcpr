using Dhcpr.Core;
using Dhcpr.Dns.Core.DynamicDns;

using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Dhcpr.Dns.Core.UnitTests;

internal static class DynamicDnsTestHelpers
{
    public static DynamicDnsStore CreateStore(
        string? dataPath = null,
        DynamicDnsConfiguration? config = null)
    {
        dataPath ??= Path.Combine(Path.GetTempPath(), "dhcpr-dyndns-" + Guid.NewGuid().ToString("n"));
        Directory.CreateDirectory(dataPath);

        config ??= new DynamicDnsConfiguration
        {
            Enabled = true,
            Username = "user",
            Password = "pass",
            TtlSeconds = 60
        };

        return new DynamicDnsStore(
            new StaticOptionsMonitor<ApplicationConfiguration>(new ApplicationConfiguration { DataPath = dataPath }),
            new StaticOptionsMonitor<DynamicDnsConfiguration>(config),
            NullLogger<DynamicDnsStore>.Instance);
    }

    public sealed class StaticOptionsMonitor<T> : IOptionsMonitor<T>
    {
        public StaticOptionsMonitor(T current) => CurrentValue = current;
        public T CurrentValue { get; }
        public T Get(string? name) => CurrentValue;
        public IDisposable? OnChange(Action<T, string?> listener) => null;
    }
}
