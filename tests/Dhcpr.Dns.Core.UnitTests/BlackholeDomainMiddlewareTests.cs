using System.Net;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Resolvers.Caching;
using Dhcpr.Dns.Core.Resolvers.Resolvers.Recursive;

using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

using NSubstitute;

namespace Dhcpr.Dns.Core.UnitTests;

public class BlackholeDomainMiddlewareTests
{
    [Theory]
    [InlineData("dhitc.com")]
    [InlineData("www.dhitc.com")]
    [InlineData("a.b.dhitc.com")]
    public async Task BlackholedNameReturnsNxDomain(string qname)
    {
        var inner = Substitute.For<IDomainMessageMiddleware>();
        var middleware = Create(inner, "dhitc.com");
        var request = DomainMessage.CreateRequest(qname, DomainRecordType.A);
        var context = new DomainMessageContext(
            new IPEndPoint(IPAddress.Loopback, 53000),
            new IPEndPoint(IPAddress.Loopback, 53),
            request);

        var result = await middleware.ProcessAsync(context, CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal(DomainResponseCode.NameError, result!.Flags.ResponseCode);
        await inner.DidNotReceiveWithAnyArgs()
            .ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>());
    }

    [Theory]
    [InlineData("a.b.localdomain")]
    [InlineData("www.example.localdomain")]
    [InlineData("_avatars-sec._tcp.daynix.com.localdomain")]
    [InlineData("A.B.LOCALDOMAIN")]
    public async Task RegexBlackholesMultiLabelLocaldomain(string qname)
    {
        var inner = Substitute.For<IDomainMessageMiddleware>();
        var middleware = Create(inner, @".+\..+\.localdomain$");
        var request = DomainMessage.CreateRequest(qname, DomainRecordType.A);
        var context = new DomainMessageContext(
            new IPEndPoint(IPAddress.Loopback, 53000),
            new IPEndPoint(IPAddress.Loopback, 53),
            request);

        var result = await middleware.ProcessAsync(context, CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal(DomainResponseCode.NameError, result!.Flags.ResponseCode);
        await inner.DidNotReceiveWithAnyArgs()
            .ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>());
    }

    [Theory]
    [InlineData("host.localdomain")]
    [InlineData("localdomain")]
    [InlineData("example.com")]
    public async Task RegexDoesNotBlackholeTwoLabelLocaldomain(string qname)
    {
        var request = DomainMessage.CreateRequest(qname, DomainRecordType.A);
        var response = DomainMessage.CreateResponse(request, responseCode: DomainResponseCode.NoError);
        var inner = Substitute.For<IDomainMessageMiddleware>();
        inner.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(_ => new ValueTask<DomainMessage>(response));

        var middleware = Create(inner, @".+\..+\.localdomain$");
        var context = new DomainMessageContext(
            new IPEndPoint(IPAddress.Loopback, 53000),
            new IPEndPoint(IPAddress.Loopback, 53),
            request);

        var result = await middleware.ProcessAsync(context, CancellationToken.None);

        Assert.Same(response, result);
        await inner.Received(1).ProcessAsync(context, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task CachedNxDomainSkipsBlackholeOnTheNextLookup()
    {
        var inner = Substitute.For<IDomainMessageMiddleware>();
        var blackhole = Create(inner, @".+\..+\.localdomain$");
        var cache = new DnsResponseCache(new MemoryCache(new MemoryCacheOptions { SizeLimit = 10_000 }));
        var pipeline = new CacheResolverDecorator(blackhole, cache, Substitute.For<IServiceScopeFactory>());
        var request = DomainMessage.CreateRequest("a.b.localdomain", DomainRecordType.A);
        var firstContext = new DomainMessageContext(
            new IPEndPoint(IPAddress.Loopback, 53000),
            new IPEndPoint(IPAddress.Loopback, 53),
            request);
        var secondContext = new DomainMessageContext(
            new IPEndPoint(IPAddress.Loopback, 53000),
            new IPEndPoint(IPAddress.Loopback, 53),
            DomainMessage.CreateRequest("a.b.localdomain", DomainRecordType.A));

        var first = await pipeline.ProcessAsync(firstContext, CancellationToken.None);
        var second = await pipeline.ProcessAsync(secondContext, CancellationToken.None);

        Assert.Equal(DomainResponseCode.NameError, first!.Flags.ResponseCode);
        Assert.Equal("Blackhole", firstContext.AnsweredBy);
        Assert.Equal(DomainResponseCode.NameError, second!.Flags.ResponseCode);
        Assert.True(secondContext.CacheHit);
        Assert.Equal("Cache", secondContext.AnsweredBy);
        await inner.DidNotReceiveWithAnyArgs()
            .ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task OtherNamesPassThrough()
    {
        var request = DomainMessage.CreateRequest("example.com", DomainRecordType.A);
        var response = DomainMessage.CreateResponse(request, responseCode: DomainResponseCode.NoError);
        var inner = Substitute.For<IDomainMessageMiddleware>();
        inner.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(_ => new ValueTask<DomainMessage>(response));

        var middleware = Create(inner, "dhitc.com");
        var context = new DomainMessageContext(
            new IPEndPoint(IPAddress.Loopback, 53000),
            new IPEndPoint(IPAddress.Loopback, 53),
            request);

        var result = await middleware.ProcessAsync(context, CancellationToken.None);

        Assert.Same(response, result);
        await inner.Received(1).ProcessAsync(context, Arg.Any<CancellationToken>());
    }

    private static BlackholeDomainMiddleware Create(IDomainMessageMiddleware inner, params string[] domains)
    {
        var monitor = Substitute.For<IOptionsMonitor<DnsConfiguration>>();
        monitor.CurrentValue.Returns(new DnsConfiguration { BlackholeDomains = domains });
        return new BlackholeDomainMiddleware(inner, monitor);
    }
}
