using System.Net;

using Dhcpr.Dns.Core.Protocol;

namespace Dhcpr.Dns.Core.UnitTests;

public class DnsServerCookieFactoryTests
{
    private static readonly byte[] Secret = Enumerable.Range(1, 32).Select(i => (byte)i).ToArray();
    private static readonly byte[] ClientCookie = [1, 2, 3, 4, 5, 6, 7, 8];
    private static readonly IPAddress Client = IPAddress.Parse("203.0.113.10");
    private static readonly DateTimeOffset FrozenNow = new(2026, 9, 20, 14, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Create_IsValid_ForSameAddress()
    {
        var factory = Factory();
        var server = factory.Create(ClientCookie, Client);

        Assert.Equal(DnsServerCookieFactory.ServerCookieLength, server.Length);
        Assert.True(factory.IsValid(ClientCookie, server.AsSpan(), Client));
    }

    [Fact]
    public void IsValid_RejectsOtherAddress()
    {
        var factory = Factory();
        var server = factory.Create(ClientCookie, Client);

        Assert.False(factory.IsValid(ClientCookie, server.AsSpan(), IPAddress.Parse("198.51.100.20")));
    }

    [Fact]
    public void IsValid_TreatsMappedIpv4AsIpv4()
    {
        var factory = Factory();
        var mapped = IPAddress.Parse("::ffff:203.0.113.10");
        var server = factory.Create(ClientCookie, mapped);

        Assert.True(factory.IsValid(ClientCookie, server.AsSpan(), Client));
        Assert.True(factory.IsValid(ClientCookie, server.AsSpan(), mapped));
    }

    [Fact]
    public void IsValid_RejectsTamperedHash()
    {
        var factory = Factory();
        var server = factory.Create(ClientCookie, Client).ToArray();
        server[^1] ^= 0xFF;

        Assert.False(factory.IsValid(ClientCookie, server, Client));
    }

    [Fact]
    public void IsValid_RejectsExpiredCookie()
    {
        var mintedAt = new FrozenTimeProvider(FrozenNow);
        var later = new FrozenTimeProvider(FrozenNow + DnsServerCookieFactory.Lifetime + TimeSpan.FromSeconds(1));
        var minted = Factory(mintedAt);
        var server = minted.Create(ClientCookie, Client);
        var validator = Factory(later);

        Assert.False(validator.IsValid(ClientCookie, server.AsSpan(), Client));
    }

    [Fact]
    public void IsValid_AcceptsCookieInsideLifetime()
    {
        var mintedAt = new FrozenTimeProvider(FrozenNow);
        var later = new FrozenTimeProvider(FrozenNow + DnsServerCookieFactory.Lifetime - TimeSpan.FromMinutes(1));
        var minted = Factory(mintedAt);
        var server = minted.Create(ClientCookie, Client);
        var validator = Factory(later);

        Assert.True(validator.IsValid(ClientCookie, server.AsSpan(), Client));
    }

    [Fact]
    public void IsValid_RejectsWrongLength()
    {
        var factory = Factory();
        Assert.False(factory.IsValid(ClientCookie, [1, 2, 3], Client));
    }

    private static DnsServerCookieFactory Factory(TimeProvider? time = null)
        => new(new StaticDnsServerCookieSecretSource(Secret), time ?? new FrozenTimeProvider(FrozenNow));

    private sealed class FrozenTimeProvider : TimeProvider
    {
        private readonly DateTimeOffset _utc;

        public FrozenTimeProvider(DateTimeOffset utc) => _utc = utc.ToUniversalTime();

        public override DateTimeOffset GetUtcNow() => _utc;
    }
}
