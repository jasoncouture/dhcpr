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
        var dns = Substitute.For<IOptionsMonitor<DnsConfiguration>>();
        dns.OnChange(Arg.Do<Action<DnsConfiguration, string?>>(listener => onChange = listener))
            .Returns(Substitute.For<IDisposable>());
        var tls = Substitute.For<IOptionsMonitor<TlsConfiguration>>();
        tls.OnChange(Arg.Any<Action<TlsConfiguration, string?>>())
            .Returns(Substitute.For<IDisposable>());

        using var invalidator = new DnsConfigurationCacheInvalidator(dns, tls, cache);
        Assert.NotNull(onChange);

        onChange!(new DnsConfiguration(), Options.DefaultName);
        cache.Received(1).Clear();
    }

    [Fact]
    public void ClearsCacheWhenTlsOptionsChange()
    {
        var cache = Substitute.For<IDnsResponseCache>();
        Action<TlsConfiguration, string?>? onChange = null;
        var dns = Substitute.For<IOptionsMonitor<DnsConfiguration>>();
        dns.OnChange(Arg.Any<Action<DnsConfiguration, string?>>())
            .Returns(Substitute.For<IDisposable>());
        var tls = Substitute.For<IOptionsMonitor<TlsConfiguration>>();
        tls.OnChange(Arg.Do<Action<TlsConfiguration, string?>>(listener => onChange = listener))
            .Returns(Substitute.For<IDisposable>());

        using var invalidator = new DnsConfigurationCacheInvalidator(dns, tls, cache);
        Assert.NotNull(onChange);

        onChange!(new TlsConfiguration(), Options.DefaultName);
        cache.Received(1).Clear();
    }
}
