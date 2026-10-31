using Dhcpr.Server.Orleans.DnsCookies;

using Microsoft.Extensions.Logging.Abstractions;

using NSubstitute;

namespace Dhcpr.Server.UnitTests;

public class DnsServerCookieSecretGrainTests
{
    [Fact]
    public async Task OnActivateBootstrapsFromLocalSnapshot()
    {
        var secret = Enumerable.Range(1, 32).Select(i => (byte)i).ToArray();
        var snapshot = Substitute.For<IDnsServerCookieSecretSnapshot>();
        snapshot.Get().Returns(secret);
        var grain = new DnsServerCookieSecretGrain(snapshot, NullLogger<DnsServerCookieSecretGrain>.Instance);

        await grain.OnActivateAsync(CancellationToken.None);
        var current = await grain.GetOrCreateAsync();

        Assert.Equal(secret, current);
    }

    [Fact]
    public async Task GetOrCreateMintsOnce()
    {
        var snapshot = Substitute.For<IDnsServerCookieSecretSnapshot>();
        var grain = new DnsServerCookieSecretGrain(snapshot, NullLogger<DnsServerCookieSecretGrain>.Instance);
        await grain.OnActivateAsync(CancellationToken.None);

        var first = await grain.GetOrCreateAsync();
        var second = await grain.GetOrCreateAsync();

        Assert.Equal(32, first.Length);
        Assert.Equal(first, second);
    }

    [Fact]
    public async Task SubscribeTakesKnownSecretWhenGrainIsEmpty()
    {
        var known = Enumerable.Range(2, 32).Select(i => (byte)i).ToArray();
        var snapshot = Substitute.For<IDnsServerCookieSecretSnapshot>();
        var grain = new DnsServerCookieSecretGrain(snapshot, NullLogger<DnsServerCookieSecretGrain>.Instance);
        await grain.OnActivateAsync(CancellationToken.None);
        var observer = Substitute.For<IDnsServerCookieSecretObserver>();

        await grain.SubscribeAsync(observer, known, CancellationToken.None);
        var current = await grain.GetOrCreateAsync();

        Assert.Equal(known, current);
        await observer.Received(1).OnSecretAsync(known, Arg.Any<CancellationToken>());
    }
}

public class OrleansDnsServerCookieSecretSourceTests
{
    [Fact]
    public void TryGetSecret_FalseWhenEmpty()
    {
        var snapshot = Substitute.For<IDnsServerCookieSecretSnapshot>();
        var source = new OrleansDnsServerCookieSecretSource(snapshot);

        Assert.False(source.TryGetSecret(out var secret));
        Assert.True(secret.IsEmpty);
    }

    [Fact]
    public void TryGetSecret_ReadsSnapshot()
    {
        var secret = Enumerable.Range(1, 32).Select(i => (byte)i).ToArray();
        var snapshot = Substitute.For<IDnsServerCookieSecretSnapshot>();
        snapshot.Get().Returns(secret);
        var source = new OrleansDnsServerCookieSecretSource(snapshot);

        Assert.True(source.TryGetSecret(out var current));
        Assert.True(current.Span.SequenceEqual(secret));
    }
}
