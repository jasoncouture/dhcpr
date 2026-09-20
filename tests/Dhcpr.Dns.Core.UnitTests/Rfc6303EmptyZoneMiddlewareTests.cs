using System.Net;

using Dhcpr.Dns.Core.Authoritative;
using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Protocol.RecordData;
using Dhcpr.Dns.Core.Resolvers.Caching;
using Dhcpr.Dns.Core.Resolvers.Resolvers.Recursive;

using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;

using NSubstitute;

namespace Dhcpr.Dns.Core.UnitTests;

public class Rfc6303EmptyZoneMiddlewareTests
{
    [Theory]
    [InlineData("232.0.168.192.in-addr.arpa")]
    [InlineData("1.0.0.127.in-addr.arpa")]
    [InlineData("1.0.10.in-addr.arpa")]
    [InlineData("5.16.172.in-addr.arpa")]
    [InlineData("1.1.64.100.in-addr.arpa")]
    public async Task PrivateReversePtrIsNxDomain(string name)
    {
        var inner = Substitute.For<IDomainMessageMiddleware>();
        var middleware = Create(inner);
        var context = Context(DomainMessage.CreateRequest(name, DomainRecordType.PTR));

        var result = await middleware.ProcessAsync(context, CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal(DomainResponseCode.NameError, result!.Flags.ResponseCode);
        Assert.Equal("rfc6303", context.AnsweredBy);
        Assert.Contains(result.Records.Authorities, r => r.Type is DomainRecordType.SOA);
        await inner.DidNotReceiveWithAnyArgs()
            .ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task ApexNsIsLocal()
    {
        var inner = Substitute.For<IDomainMessageMiddleware>();
        var middleware = Create(inner);
        var context = Context(DomainMessage.CreateRequest("168.192.in-addr.arpa", DomainRecordType.NS));

        var result = await middleware.ProcessAsync(context, CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal(DomainResponseCode.NoError, result!.Flags.ResponseCode);
        Assert.Contains(result.Records.Answers, r => r.Type is DomainRecordType.NS);
    }

    [Fact]
    public async Task PublicReverseFallsThrough()
    {
        var inner = Substitute.For<IDomainMessageMiddleware>();
        var request = DomainMessage.CreateRequest("4.4.8.8.in-addr.arpa", DomainRecordType.PTR);
        var response = DomainMessage.CreateResponse(request, responseCode: DomainResponseCode.NoError);
        inner.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(_ => new ValueTask<DomainMessage>(response));
        var middleware = Create(inner);
        var context = Context(request);

        var result = await middleware.ProcessAsync(context, CancellationToken.None);

        Assert.Same(response, result);
        await inner.Received(1).ProcessAsync(context, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task CachedNxDomainSkipsSuffixMatchOnTheNextLookup()
    {
        var inner = Substitute.For<IDomainMessageMiddleware>();
        var cache = new DnsResponseCache(new MemoryCache(new MemoryCacheOptions { SizeLimit = 10_000 }));
        var pipeline = new CacheResolverDecorator(Create(inner), cache);
        var firstContext = Context(DomainMessage.CreateRequest("232.0.168.192.in-addr.arpa", DomainRecordType.PTR));
        var secondContext = Context(DomainMessage.CreateRequest("232.0.168.192.in-addr.arpa", DomainRecordType.PTR));

        var first = await pipeline.ProcessAsync(firstContext, CancellationToken.None);
        var second = await pipeline.ProcessAsync(secondContext, CancellationToken.None);

        Assert.Equal(DomainResponseCode.NameError, first!.Flags.ResponseCode);
        Assert.Equal("rfc6303", firstContext.AnsweredBy);
        Assert.Equal(DomainResponseCode.NameError, second!.Flags.ResponseCode);
        Assert.True(secondContext.CacheHit);
        Assert.Equal("Cache", secondContext.AnsweredBy);
        await inner.DidNotReceiveWithAnyArgs()
            .ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public void MatchRejectsPublicInAddr()
    {
        Assert.False(Rfc6303EmptyZones.TryMatch(new DomainLabels("4.4.8.8.in-addr.arpa"), out _, out _));
        Assert.True(Rfc6303EmptyZones.TryMatch(new DomainLabels("232.0.168.192.in-addr.arpa"), out var zone, out var apex));
        Assert.Equal("168.192.in-addr.arpa", zone);
        Assert.False(apex);
    }

    private static Rfc6303EmptyZoneMiddleware Create(
        IDomainMessageMiddleware inner,
        IAuthoritativeZoneStore? zones = null)
    {
        var monitor = Substitute.For<IOptionsMonitor<DnsConfiguration>>();
        monitor.CurrentValue.Returns(new DnsConfiguration());
        return new Rfc6303EmptyZoneMiddleware(
            inner,
            zones ?? Substitute.For<IAuthoritativeZoneStore>(),
            monitor);
    }

    private static DomainMessageContext Context(DomainMessage request)
        => new(
            new IPEndPoint(IPAddress.Loopback, 53000),
            new IPEndPoint(IPAddress.Loopback, 53),
            request);
}
