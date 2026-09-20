using System.Net;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Protocol.RecordData;
using Dhcpr.Dns.Core.Resolvers.Caching;
using Dhcpr.Dns.Core.Resolvers.Resolvers.Recursive;

using Microsoft.Extensions.Caching.Memory;

using NSubstitute;

namespace Dhcpr.Dns.Core.UnitTests;

public class BindChaosMiddlewareTests
{
    [Theory]
    [InlineData("version.bind", BindChaosMiddleware.VersionText)]
    [InlineData("version.server", BindChaosMiddleware.VersionText)]
    [InlineData("VERSION.BIND", BindChaosMiddleware.VersionText)]
    [InlineData("hostname.bind", BindChaosMiddleware.HostnameText)]
    [InlineData("id.server", BindChaosMiddleware.HostnameText)]
    [InlineData("authors.bind", BindChaosMiddleware.AuthorsText)]
    public async Task ChaosTxtLooksLikeBind(string qname, string expected)
    {
        var inner = Substitute.For<IDomainMessageMiddleware>();
        var middleware = new BindChaosMiddleware(inner);
        var request = DomainMessage.CreateRequest(qname, DomainRecordType.TXT, DomainRecordClass.CH);
        var context = Context(request);

        var result = await middleware.ProcessAsync(context, CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal(DomainResponseCode.NoError, result!.Flags.ResponseCode);
        Assert.True(result.Flags.Authoritative);
        Assert.True(result.Flags.RecursionAvailable);
        Assert.False(result.Flags.Authentic);
        var answer = Assert.Single(result.Records.Answers);
        Assert.Equal(DomainRecordType.TXT, answer.Type);
        Assert.Equal(DomainRecordClass.CH, answer.Class);
        Assert.Equal(BindChaosMiddleware.IdentityTtl, answer.TimeToLive);
        var text = Assert.IsType<TextData>(answer.Data);
        Assert.Equal(expected, text.Text);
        Assert.Equal("bind-chaos", context.AnsweredBy);
        Assert.False(context.DoNotCacheResponse);
        await inner.DidNotReceiveWithAnyArgs()
            .ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task IpInfoReturnsClientIpv4()
    {
        var inner = Substitute.For<IDomainMessageMiddleware>();
        var middleware = new BindChaosMiddleware(inner);
        var request = DomainMessage.CreateRequest("ip.info", DomainRecordType.TXT, DomainRecordClass.CH);
        var context = new DomainMessageContext(
            new IPEndPoint(IPAddress.Parse("203.0.113.9"), 53000),
            new IPEndPoint(IPAddress.Loopback, 53),
            request);

        var result = await middleware.ProcessAsync(context, CancellationToken.None);

        var text = Assert.IsType<TextData>(Assert.Single(result!.Records.Answers).Data);
        Assert.Equal("203.0.113.9", text.Text);
        Assert.True(context.DoNotCacheResponse);
        await inner.DidNotReceiveWithAnyArgs()
            .ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task IpInfoReturnsClientIpv6()
    {
        var inner = Substitute.For<IDomainMessageMiddleware>();
        var middleware = new BindChaosMiddleware(inner);
        var request = DomainMessage.CreateRequest("IP.INFO", DomainRecordType.TXT, DomainRecordClass.CH);
        var context = new DomainMessageContext(
            new IPEndPoint(IPAddress.Parse("2001:db8::5"), 53000),
            new IPEndPoint(IPAddress.IPv6Loopback, 53),
            request);

        var result = await middleware.ProcessAsync(context, CancellationToken.None);

        var text = Assert.IsType<TextData>(Assert.Single(result!.Records.Answers).Data);
        Assert.Equal(IPAddress.Parse("2001:db8::5").ToString(), text.Text);
    }

    [Fact]
    public async Task IpInfoMapsIpv4MappedIpv6()
    {
        var inner = Substitute.For<IDomainMessageMiddleware>();
        var middleware = new BindChaosMiddleware(inner);
        var request = DomainMessage.CreateRequest("ip.info", DomainRecordType.TXT, DomainRecordClass.CH);
        var context = new DomainMessageContext(
            new IPEndPoint(IPAddress.Parse("::ffff:198.51.100.10"), 53000),
            new IPEndPoint(IPAddress.Loopback, 53),
            request);

        var result = await middleware.ProcessAsync(context, CancellationToken.None);

        var text = Assert.IsType<TextData>(Assert.Single(result!.Records.Answers).Data);
        Assert.Equal("198.51.100.10", text.Text);
    }

    [Fact]
    public async Task ChaosAnyReturnsHostnameTxt()
    {
        var inner = Substitute.For<IDomainMessageMiddleware>();
        var middleware = new BindChaosMiddleware(inner);
        var request = DomainMessage.CreateRequest("id.server", DomainRecordType.ANY, DomainRecordClass.CH);

        var result = await middleware.ProcessAsync(Context(request), CancellationToken.None);

        Assert.NotNull(result);
        var answer = Assert.Single(result!.Records.Answers);
        Assert.Equal(DomainRecordType.TXT, answer.Type);
        Assert.Equal(BindChaosMiddleware.HostnameText, Assert.IsType<TextData>(answer.Data).Text);
    }

    [Fact]
    public async Task ChaosOtherTypeIsNodata()
    {
        var inner = Substitute.For<IDomainMessageMiddleware>();
        var middleware = new BindChaosMiddleware(inner);
        var request = DomainMessage.CreateRequest("version.bind", DomainRecordType.A, DomainRecordClass.CH);

        var result = await middleware.ProcessAsync(Context(request), CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal(DomainResponseCode.NoError, result!.Flags.ResponseCode);
        Assert.Empty(result.Records.Answers);
        await inner.DidNotReceiveWithAnyArgs()
            .ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>());
    }

    [Theory]
    [InlineData(DomainRecordClass.IN)]
    [InlineData(DomainRecordClass.HS)]
    [InlineData(DomainRecordClass.CS)]
    [InlineData(DomainRecordClass.Any)]
    [InlineData(DomainRecordClass.None)]
    [InlineData((DomainRecordClass)99)]
    public async Task NonChaosPassesThrough(DomainRecordClass @class)
    {
        var request = DomainMessage.CreateRequest("example.com", DomainRecordType.TXT, @class);
        var response = DomainMessage.CreateResponse(request, responseCode: DomainResponseCode.NameError);
        var inner = Substitute.For<IDomainMessageMiddleware>();
        inner.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(_ => new ValueTask<DomainMessage?>(response));
        var middleware = new BindChaosMiddleware(inner);

        var result = await middleware.ProcessAsync(Context(request), CancellationToken.None);

        Assert.Same(response, result);
        await inner.Received(1).ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task CachedIdentitySkipsBindChaosOnTheNextLookup()
    {
        var inner = Substitute.For<IDomainMessageMiddleware>();
        var chaos = new BindChaosMiddleware(inner);
        var cache = new DnsResponseCache(new MemoryCache(new MemoryCacheOptions { SizeLimit = 10_000 }));
        var pipeline = new CacheResolverDecorator(chaos, cache);
        var firstContext = Context(
            DomainMessage.CreateRequest("version.bind", DomainRecordType.TXT, DomainRecordClass.CH));
        var secondContext = Context(
            DomainMessage.CreateRequest("version.bind", DomainRecordType.TXT, DomainRecordClass.CH));

        var first = await pipeline.ProcessAsync(firstContext, CancellationToken.None);
        var second = await pipeline.ProcessAsync(secondContext, CancellationToken.None);

        Assert.Equal(BindChaosMiddleware.VersionText, Assert.IsType<TextData>(Assert.Single(first!.Records.Answers).Data).Text);
        Assert.Equal("bind-chaos", firstContext.AnsweredBy);
        Assert.Equal(BindChaosMiddleware.VersionText, Assert.IsType<TextData>(Assert.Single(second!.Records.Answers).Data).Text);
        Assert.True(secondContext.CacheHit);
        Assert.Equal("Cache", secondContext.AnsweredBy);
        await inner.DidNotReceiveWithAnyArgs()
            .ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task IpInfoIsNotServedFromAnotherClientsCache()
    {
        var inner = Substitute.For<IDomainMessageMiddleware>();
        var chaos = new BindChaosMiddleware(inner);
        var cache = new DnsResponseCache(new MemoryCache(new MemoryCacheOptions { SizeLimit = 10_000 }));
        var pipeline = new CacheResolverDecorator(chaos, cache);
        var request = DomainMessage.CreateRequest("ip.info", DomainRecordType.TXT, DomainRecordClass.CH);
        var firstContext = new DomainMessageContext(
            new IPEndPoint(IPAddress.Parse("203.0.113.9"), 53000),
            new IPEndPoint(IPAddress.Loopback, 53),
            request);
        var secondContext = new DomainMessageContext(
            new IPEndPoint(IPAddress.Parse("198.51.100.20"), 53000),
            new IPEndPoint(IPAddress.Loopback, 53),
            DomainMessage.CreateRequest("ip.info", DomainRecordType.TXT, DomainRecordClass.CH));

        var first = await pipeline.ProcessAsync(firstContext, CancellationToken.None);
        var second = await pipeline.ProcessAsync(secondContext, CancellationToken.None);

        Assert.Equal("203.0.113.9", Assert.IsType<TextData>(Assert.Single(first!.Records.Answers).Data).Text);
        Assert.True(firstContext.DoNotCacheResponse);
        Assert.Equal("198.51.100.20", Assert.IsType<TextData>(Assert.Single(second!.Records.Answers).Data).Text);
        Assert.False(secondContext.CacheHit);
        Assert.Equal("bind-chaos", secondContext.AnsweredBy);
    }

    [Fact]
    public async Task InternetClassPassesThrough()
    {
        var request = DomainMessage.CreateRequest("version.bind", DomainRecordType.TXT);
        var response = DomainMessage.CreateResponse(request, responseCode: DomainResponseCode.NameError);
        var inner = Substitute.For<IDomainMessageMiddleware>();
        inner.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(_ => new ValueTask<DomainMessage?>(response));
        var middleware = new BindChaosMiddleware(inner);

        var result = await middleware.ProcessAsync(Context(request), CancellationToken.None);

        Assert.Same(response, result);
        await inner.Received(1).ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>());
    }

    [Theory]
    [InlineData("foo.bind")]
    [InlineData("example.com")]
    public async Task OtherChaosNamesAreLocalNxdomain(string qname)
    {
        var inner = Substitute.For<IDomainMessageMiddleware>();
        var middleware = new BindChaosMiddleware(inner);
        var request = DomainMessage.CreateRequest(qname, DomainRecordType.TXT, DomainRecordClass.CH);
        var context = Context(request);

        var result = await middleware.ProcessAsync(context, CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal(DomainResponseCode.NameError, result!.Flags.ResponseCode);
        Assert.Empty(result.Records.Answers);
        Assert.True(result.Flags.Authoritative);
        Assert.Equal("bind-chaos", context.AnsweredBy);
        await inner.DidNotReceiveWithAnyArgs()
            .ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>());
    }

    private static DomainMessageContext Context(DomainMessage request)
        => new(
            new IPEndPoint(IPAddress.Loopback, 53000),
            new IPEndPoint(IPAddress.Loopback, 53),
            request);
}
