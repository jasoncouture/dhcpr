using System.Net;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Resolvers.Caching;
using Dhcpr.Dns.Core.Resolvers.Resolvers.Recursive;

using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

using NSubstitute;

namespace Dhcpr.Dns.Core.UnitTests;

public class UnsupportedQueryTypeMiddlewareTests
{
    [Theory]
    [InlineData(DomainRecordType.HINFO, DomainResponseCode.Refused)]
    [InlineData(DomainRecordType.AXFR, DomainResponseCode.Refused)]
    [InlineData(DomainRecordType.IXFR, DomainResponseCode.Refused)]
    [InlineData(DomainRecordType.ANY, DomainResponseCode.NotImplemented)]
    public async Task BlockedTypeReturnsConfiguredRcodeWithoutCallingInner(
        DomainRecordType type,
        DomainResponseCode rcode)
    {
        var inner = Substitute.For<IDomainMessageMiddleware>();
        var middleware = new UnsupportedQueryTypeMiddleware(inner);
        var request = DomainMessage.CreateRequest("example.com", type);
        var context = new DomainMessageContext(
            new IPEndPoint(IPAddress.Loopback, 53000),
            new IPEndPoint(IPAddress.Loopback, 53),
            request);

        var result = await middleware.ProcessAsync(context, CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal(rcode, result!.Flags.ResponseCode);
        await inner.DidNotReceiveWithAnyArgs()
            .ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task UnknownTypeReturnsNotImplementedWithoutCallingInner()
    {
        var inner = Substitute.For<IDomainMessageMiddleware>();
        var middleware = new UnsupportedQueryTypeMiddleware(inner);
        var request = DomainMessage.CreateRequest("dhitc.com", (DomainRecordType)99);
        var context = new DomainMessageContext(
            new IPEndPoint(IPAddress.Loopback, 53000),
            new IPEndPoint(IPAddress.Loopback, 53),
            request);

        var result = await middleware.ProcessAsync(context, CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal(DomainResponseCode.NotImplemented, result!.Flags.ResponseCode);
        await inner.DidNotReceiveWithAnyArgs()
            .ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>());
    }

    [Theory]
    [InlineData(DomainRecordClass.HS)]
    [InlineData(DomainRecordClass.CS)]
    [InlineData(DomainRecordClass.Any)]
    [InlineData(DomainRecordClass.None)]
    [InlineData((DomainRecordClass)99)]
    public async Task NonInternetNonChaosIsNotImplemented(DomainRecordClass @class)
    {
        var inner = Substitute.For<IDomainMessageMiddleware>();
        var middleware = new UnsupportedQueryTypeMiddleware(inner);
        var request = DomainMessage.CreateRequest("example.com", DomainRecordType.TXT, @class);
        var context = new DomainMessageContext(
            new IPEndPoint(IPAddress.Loopback, 53000),
            new IPEndPoint(IPAddress.Loopback, 53),
            request);

        var result = await middleware.ProcessAsync(context, CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal(DomainResponseCode.NotImplemented, result!.Flags.ResponseCode);
        Assert.Empty(result.Records.Answers);
        Assert.Equal("query-class", context.AnsweredBy);
        await inner.DidNotReceiveWithAnyArgs()
            .ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>());
    }

    [Theory]
    [InlineData(DomainRecordType.TXT)]
    [InlineData(DomainRecordType.ANY)]
    [InlineData(DomainRecordType.HINFO)]
    public async Task ChaosClassPassesThrough(DomainRecordType type)
    {
        var request = DomainMessage.CreateRequest("version.bind", type, DomainRecordClass.CH);
        var response = DomainMessage.CreateResponse(request, responseCode: DomainResponseCode.NoError);
        var inner = Substitute.For<IDomainMessageMiddleware>();
        inner.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(_ => new ValueTask<DomainMessage>(response));
        var middleware = new UnsupportedQueryTypeMiddleware(inner);
        var context = new DomainMessageContext(
            new IPEndPoint(IPAddress.Loopback, 53000),
            new IPEndPoint(IPAddress.Loopback, 53),
            request);

        var result = await middleware.ProcessAsync(context, CancellationToken.None);

        Assert.Same(response, result);
        await inner.Received(1).ProcessAsync(context, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task KnownTypePassesThrough()
    {
        var request = DomainMessage.CreateRequest("example.com", DomainRecordType.A);
        var response = DomainMessage.CreateResponse(request, responseCode: DomainResponseCode.NoError);
        var inner = Substitute.For<IDomainMessageMiddleware>();
        inner.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(_ => new ValueTask<DomainMessage>(response));

        var middleware = new UnsupportedQueryTypeMiddleware(inner);
        var context = new DomainMessageContext(
            new IPEndPoint(IPAddress.Loopback, 53000),
            new IPEndPoint(IPAddress.Loopback, 53),
            request);

        var result = await middleware.ProcessAsync(context, CancellationToken.None);

        Assert.Same(response, result);
        await inner.Received(1).ProcessAsync(context, Arg.Any<CancellationToken>());
    }

    [Theory]
    [InlineData(DomainRecordType.ANY, DomainResponseCode.NotImplemented)]
    [InlineData(DomainRecordType.HINFO, DomainResponseCode.Refused)]
    [InlineData(DomainRecordType.AXFR, DomainResponseCode.Refused)]
    public async Task CachedPolicyAnswerSkipsTypeCheckOnTheNextLookup(
        DomainRecordType type,
        DomainResponseCode rcode)
    {
        var inner = Substitute.For<IDomainMessageMiddleware>();
        var cache = new DnsResponseCache(new MemoryCache(new MemoryCacheOptions { SizeLimit = 10_000 }));
        var pipeline = new CacheResolverDecorator(new UnsupportedQueryTypeMiddleware(inner), cache, Substitute.For<IServiceScopeFactory>(), Substitute.For<ILogger<CacheResolverDecorator>>());
        var firstContext = Context(DomainMessage.CreateRequest("example.com", type));
        var secondContext = Context(DomainMessage.CreateRequest("example.com", type));

        var first = await pipeline.ProcessAsync(firstContext, CancellationToken.None);
        var second = await pipeline.ProcessAsync(secondContext, CancellationToken.None);

        Assert.Equal(rcode, first!.Flags.ResponseCode);
        Assert.Equal(rcode, second!.Flags.ResponseCode);
        Assert.True(secondContext.CacheHit);
        Assert.Equal("Cache", secondContext.AnsweredBy);
        await inner.DidNotReceiveWithAnyArgs()
            .ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task CachedClassRejectionSkipsClassCheckOnTheNextLookup()
    {
        var inner = Substitute.For<IDomainMessageMiddleware>();
        var cache = new DnsResponseCache(new MemoryCache(new MemoryCacheOptions { SizeLimit = 10_000 }));
        var pipeline = new CacheResolverDecorator(new UnsupportedQueryTypeMiddleware(inner), cache, Substitute.For<IServiceScopeFactory>(), Substitute.For<ILogger<CacheResolverDecorator>>());
        var firstContext = Context(DomainMessage.CreateRequest("example.com", DomainRecordType.TXT, DomainRecordClass.HS));
        var secondContext = Context(DomainMessage.CreateRequest("example.com", DomainRecordType.TXT, DomainRecordClass.HS));

        var first = await pipeline.ProcessAsync(firstContext, CancellationToken.None);
        var second = await pipeline.ProcessAsync(secondContext, CancellationToken.None);

        Assert.Equal(DomainResponseCode.NotImplemented, first!.Flags.ResponseCode);
        Assert.Equal(DomainResponseCode.NotImplemented, second!.Flags.ResponseCode);
        Assert.True(secondContext.CacheHit);
        Assert.Equal("Cache", secondContext.AnsweredBy);
        await inner.DidNotReceiveWithAnyArgs()
            .ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>());
    }

    private static DomainMessageContext Context(DomainMessage request)
        => new(
            new IPEndPoint(IPAddress.Loopback, 53000),
            new IPEndPoint(IPAddress.Loopback, 53),
            request);
}
