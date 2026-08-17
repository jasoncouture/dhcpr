using Dhcpr.Core;
using Dhcpr.Dns.Core.DynamicDns;

using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

using NSubstitute;

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
            Monitor(new ApplicationConfiguration { DataPath = dataPath }),
            Monitor(config),
            NullLogger<DynamicDnsStore>.Instance);
    }

    private static IOptionsMonitor<T> Monitor<T>(T value)
    {
        var monitor = Substitute.For<IOptionsMonitor<T>>();
        monitor.CurrentValue.Returns(value);
        monitor.Get(Arg.Any<string?>()).Returns(value);
        return monitor;
    }
}
