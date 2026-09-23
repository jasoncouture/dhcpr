using System.Net;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Protocol.RecordData;
using Dhcpr.Dns.Core.Resolvers.Caching;
using Dhcpr.Dns.Core.Resolvers.Resolvers.Recursive;

using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;

using NSubstitute;

namespace Dhcpr.Dns.Core.UnitTests;

public class AddressPrefetchMiddlewareTests
{
    [Theory]
    [InlineData(DomainRecordType.A, DomainRecordType.AAAA)]
    [InlineData(DomainRecordType.AAAA, DomainRecordType.A)]
    public async Task ExternalNoerrorSchedulesSiblingPrefetch(
        DomainRecordType asked,
        DomainRecordType sibling)
    {
        var (middleware, cache, client, started) = Create(cacheHit: false);
        var request = DomainMessage.CreateRequest("example.com", asked);
        var response = DomainMessage.CreateResponse(request, responseCode: DomainResponseCode.NoError);

        var inner = Substitute.For<IDomainMessageMiddleware>();
        inner.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(_ => new ValueTask<DomainMessage>(response));
        middleware = Wrap(inner, cache, client);

        var result = await middleware.ProcessAsync(Context(request), CancellationToken.None);
        Assert.Same(response, result);

        var scheduled = await started.Task.WaitAsync(TimeSpan.FromSeconds(2));
        Assert.Equal(sibling, scheduled.Questions[0].Type);
        Assert.Equal("example.com", scheduled.Questions[0].Name.ToString(), StringComparer.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task InternalHopDoesNotPrefetch()
    {
        var (middleware, _, client, started) = Create(cacheHit: false);
        var request = DomainMessage.CreateRequest("example.com", DomainRecordType.A);
        var response = DomainMessage.CreateResponse(request, responseCode: DomainResponseCode.NoError);
        var inner = Substitute.For<IDomainMessageMiddleware>();
        inner.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(_ => new ValueTask<DomainMessage>(response));
        middleware = Wrap(inner, Substitute.For<IDnsResponseCache>(), client);

        var context = Context(request) with { IsInternal = true };
        await middleware.ProcessAsync(context, CancellationToken.None);

        await Task.Delay(50);
        Assert.False(started.Task.IsCompleted);
        await client.DidNotReceiveWithAnyArgs()
            .SendPrefetchAsync(Arg.Any<DomainMessageContext>(), Arg.Any<DomainMessage>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task PrefetchHopDoesNotPrefetchAgain()
    {
        var client = Substitute.For<IInternalDomainClient>();
        var started = new TaskCompletionSource<DomainMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        client.SendPrefetchAsync(Arg.Any<DomainMessageContext>(), Arg.Any<DomainMessage>(), Arg.Any<CancellationToken>())
            .Returns(call =>
            {
                started.TrySetResult(call.Arg<DomainMessage>());
                return new ValueTask<DomainMessage>(
                    DomainMessage.CreateResponse(call.Arg<DomainMessage>(), DomainResourceRecords.Empty,
                        DomainResponseCode.NoError));
            });

        var request = DomainMessage.CreateRequest("example.com", DomainRecordType.A);
        var response = DomainMessage.CreateResponse(request, responseCode: DomainResponseCode.NoError);
        var inner = Substitute.For<IDomainMessageMiddleware>();
        inner.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(_ => new ValueTask<DomainMessage>(response));
        var middleware = Wrap(inner, Substitute.For<IDnsResponseCache>(), client);

        var context = Context(request) with { SuppressAddressPrefetch = true };
        await middleware.ProcessAsync(context, CancellationToken.None);

        await Task.Delay(50);
        Assert.False(started.Task.IsCompleted);
    }

    [Fact]
    public async Task CachedSiblingDoesNotPrefetch()
    {
        var cache = Substitute.For<IDnsResponseCache>();
        cache.TryGet(Arg.Any<DomainMessage>(), out Arg.Any<DomainMessage?>())
            .Returns(true);
        var client = Substitute.For<IInternalDomainClient>();
        var request = DomainMessage.CreateRequest("example.com", DomainRecordType.A);
        var response = DomainMessage.CreateResponse(request, responseCode: DomainResponseCode.NoError);
        var inner = Substitute.For<IDomainMessageMiddleware>();
        inner.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(_ => new ValueTask<DomainMessage>(response));
        var middleware = Wrap(inner, cache, client);

        await middleware.ProcessAsync(Context(request), CancellationToken.None);
        await Task.Delay(50);
        await client.DidNotReceiveWithAnyArgs()
            .SendPrefetchAsync(Arg.Any<DomainMessageContext>(), Arg.Any<DomainMessage>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task NxDomainDoesNotPrefetch()
    {
        var client = Substitute.For<IInternalDomainClient>();
        var request = DomainMessage.CreateRequest("nope.example", DomainRecordType.A);
        var response = DomainMessage.CreateResponse(request, responseCode: DomainResponseCode.NameError);
        var inner = Substitute.For<IDomainMessageMiddleware>();
        inner.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(_ => new ValueTask<DomainMessage>(response));
        var middleware = Wrap(inner, Substitute.For<IDnsResponseCache>(), client);

        await middleware.ProcessAsync(Context(request), CancellationToken.None);
        await Task.Delay(50);
        await client.DidNotReceiveWithAnyArgs()
            .SendPrefetchAsync(Arg.Any<DomainMessageContext>(), Arg.Any<DomainMessage>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task CacheHitDoesNotSchedulePrefetch()
    {
        var started = new TaskCompletionSource<DomainMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        var client = Substitute.For<IInternalDomainClient>();
        client.SendPrefetchAsync(Arg.Any<DomainMessageContext>(), Arg.Any<DomainMessage>(), Arg.Any<CancellationToken>())
            .Returns(call =>
            {
                started.TrySetResult(call.Arg<DomainMessage>());
                return new ValueTask<DomainMessage>(
                    DomainMessage.CreateResponse(call.Arg<DomainMessage>(), DomainResourceRecords.Empty,
                        DomainResponseCode.NoError));
            });

        var cache = new DnsResponseCache(new MemoryCache(new MemoryCacheOptions { SizeLimit = 10_000 }));
        var request = DomainMessage.CreateRequest("example.com", DomainRecordType.A);
        var response = DomainMessage.CreateResponse(
            request,
            [
                new DomainResourceRecord(
                    new DomainLabels("example.com"),
                    DomainRecordType.A,
                    DomainRecordClass.IN,
                    TimeSpan.FromSeconds(300),
                    new IPAddressData(IPAddress.Parse("192.0.2.1")))
            ],
            responseCode: DomainResponseCode.NoError);
        var inner = Substitute.For<IDomainMessageMiddleware>();
        inner.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(_ => new ValueTask<DomainMessage>(response));
        var pipeline = new CacheResolverDecorator(Wrap(inner, cache, client), cache, Substitute.For<IDnsCacheRefresh>());

        await pipeline.ProcessAsync(Context(request), CancellationToken.None);
        var scheduled = await started.Task.WaitAsync(TimeSpan.FromSeconds(2));
        Assert.Equal(DomainRecordType.AAAA, scheduled.Questions[0].Type);

        client.ClearReceivedCalls();
        var second = Context(DomainMessage.CreateRequest("example.com", DomainRecordType.A));
        await pipeline.ProcessAsync(second, CancellationToken.None);

        Assert.True(second.CacheHit);
        await Task.Delay(50);
        await client.DidNotReceiveWithAnyArgs()
            .SendPrefetchAsync(Arg.Any<DomainMessageContext>(), Arg.Any<DomainMessage>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task ClientAnswerIsNotDelayedByPrefetch()
    {
        var client = Substitute.For<IInternalDomainClient>();
        client.SendPrefetchAsync(Arg.Any<DomainMessageContext>(), Arg.Any<DomainMessage>(), Arg.Any<CancellationToken>())
            .Returns(_ => new ValueTask<DomainMessage>(new TaskCompletionSource<DomainMessage>().Task));
        var request = DomainMessage.CreateRequest("example.com", DomainRecordType.A);
        var response = DomainMessage.CreateResponse(request, responseCode: DomainResponseCode.NoError);
        var inner = Substitute.For<IDomainMessageMiddleware>();
        inner.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(_ => new ValueTask<DomainMessage>(response));
        var middleware = Wrap(inner, Substitute.For<IDnsResponseCache>(), client);

        var result = await middleware.ProcessAsync(Context(request), CancellationToken.None)
            .AsTask()
            .WaitAsync(TimeSpan.FromSeconds(1));
        Assert.Same(response, result);
    }

    private static (
        AddressPrefetchMiddleware Middleware,
        IDnsResponseCache Cache,
        IInternalDomainClient Client,
        TaskCompletionSource<DomainMessage> Started)
        Create(bool cacheHit)
    {
        var cache = Substitute.For<IDnsResponseCache>();
        cache.TryGet(Arg.Any<DomainMessage>(), out Arg.Any<DomainMessage?>()).Returns(cacheHit);
        var started = new TaskCompletionSource<DomainMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        var client = Substitute.For<IInternalDomainClient>();
        client.SendPrefetchAsync(Arg.Any<DomainMessageContext>(), Arg.Any<DomainMessage>(), Arg.Any<CancellationToken>())
            .Returns(call =>
            {
                started.TrySetResult(call.Arg<DomainMessage>());
                return new ValueTask<DomainMessage>(
                    DomainMessage.CreateResponse(call.Arg<DomainMessage>(), DomainResourceRecords.Empty,
                        DomainResponseCode.NoError));
            });
        var inner = Substitute.For<IDomainMessageMiddleware>();
        return (Wrap(inner, cache, client), cache, client, started);
    }

    private static AddressPrefetchMiddleware Wrap(
        IDomainMessageMiddleware inner,
        IDnsResponseCache cache,
        IInternalDomainClient client)
        => new(inner, cache, client, NullLogger<AddressPrefetchMiddleware>.Instance);

    private static DomainMessageContext Context(DomainMessage request)
        => new(
            new IPEndPoint(IPAddress.Loopback, 53000),
            new IPEndPoint(IPAddress.Loopback, 53),
            request);
}
