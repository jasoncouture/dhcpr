using Dhcpr.Dns.Core.Resolvers.Caching;

using Microsoft.Extensions.Options;

using NSubstitute;

namespace Dhcpr.Dns.Core.UnitTests;

public class DnsConfigurationCacheInvalidatorTests
{
    [Fact]
    public void ClearsCacheWhenOptionsChange()
    {
        var cache = Substitute.For<IDnsResponseCache>();
        Action<DnsConfiguration, string?>? onChange = null;
        var monitor = Substitute.For<IOptionsMonitor<DnsConfiguration>>();
        monitor.OnChange(Arg.Do<Action<DnsConfiguration, string?>>(listener => onChange = listener))
            .Returns(Substitute.For<IDisposable>());

        using var invalidator = new DnsConfigurationCacheInvalidator(monitor, cache);
        Assert.NotNull(onChange);

        onChange!(new DnsConfiguration(), Options.DefaultName);
        cache.Received(1).Clear();
    }
}
