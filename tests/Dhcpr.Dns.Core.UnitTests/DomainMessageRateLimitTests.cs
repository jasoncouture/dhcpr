using System.Collections.Immutable;
using System.Net;

using Dhcpr.Dns.Core;
using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Protocol.RecordData;

using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

using NSubstitute;

namespace Dhcpr.Dns.Core.UnitTests;

public class DomainMessageRateLimitTests
{
    private static readonly IPEndPoint Client = new(IPAddress.Parse("203.0.113.10"), 53_000);
    private static readonly IPEndPoint Server = new(IPAddress.Parse("192.0.2.1"), 53);

    [Theory]
    [InlineData(DnsQuerySource.Udp)]
    [InlineData(DnsQuerySource.Tcp)]
    public async Task RefusesClassicDns(DnsQuerySource source)
    {
        var limiter = Substitute.For<IUdpQueryRateLimiter>();
        limiter.Record(Arg.Any<IPAddress?>(), Arg.Any<DomainLabels>(), Arg.Any<DomainRecordType>())
            .Returns(UdpRateLimitAction.Refuse);
        var middleware = PassthroughMiddleware();
        var processor = Create(limiter, middleware);
        var context = CreateContext(source);

        var response = await processor.ExecuteAsync(context, CancellationToken.None);

        await middleware.DidNotReceive()
            .ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>());
        Assert.Equal("UdpRateLimit", context.AnsweredBy);
        Assert.NotNull(response);
        Assert.Equal(DomainResponseCode.Refused, response!.Flags.ResponseCode);
    }

    [Theory]
    [InlineData(DnsQuerySource.Udp)]
    [InlineData(DnsQuerySource.Tcp)]
    public async Task DropsClassicDns(DnsQuerySource source)
    {
        var limiter = Substitute.For<IUdpQueryRateLimiter>();
        limiter.Record(Arg.Any<IPAddress?>(), Arg.Any<DomainLabels>(), Arg.Any<DomainRecordType>())
            .Returns(UdpRateLimitAction.Drop);
        var middleware = PassthroughMiddleware();
        var processor = Create(limiter, middleware);
        var context = CreateContext(source);

        var response = await processor.ExecuteAsync(context, CancellationToken.None);

        await middleware.DidNotReceive()
            .ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>());
        Assert.Equal("UdpRateLimit", context.AnsweredBy);
        Assert.True(context.Cancel);
        Assert.Null(response);
    }

    [Fact]
    public async Task DoesNotLimitInternalHops()
    {
        var limiter = Substitute.For<IUdpQueryRateLimiter>();
        limiter.Record(Arg.Any<IPAddress?>(), Arg.Any<DomainLabels>(), Arg.Any<DomainRecordType>())
            .Returns(UdpRateLimitAction.Drop);
        var request = DomainMessage.CreateRequest("cisco.com", DomainRecordType.TXT);
        var answered = DomainMessage.CreateResponse(request, DomainResourceRecords.Empty, DomainResponseCode.NoError);
        var middleware = PassthroughMiddleware(answered);
        var processor = Create(limiter, middleware);
        var context = new DomainMessageContext(Client, Server, request) { IsInternal = true };

        var result = await processor.ExecuteAsync(context, CancellationToken.None);

        await middleware.Received(1)
            .ProcessAsync(context, Arg.Any<CancellationToken>());
        limiter.DidNotReceive()
            .Record(Arg.Any<IPAddress?>(), Arg.Any<DomainLabels>(), Arg.Any<DomainRecordType>());
        Assert.Same(answered, result);
    }

    [Fact]
    public async Task BypassCacheDoesNotSkipLimit()
    {
        var limiter = Substitute.For<IUdpQueryRateLimiter>();
        limiter.Record(Arg.Any<IPAddress?>(), Arg.Any<DomainLabels>(), Arg.Any<DomainRecordType>())
            .Returns(UdpRateLimitAction.Refuse);
        var middleware = PassthroughMiddleware();
        var processor = Create(limiter, middleware);
        var request = DomainMessage.CreateRequest("cisco.com", DomainRecordType.TXT);
        var context = new DomainMessageContext(Client, Server, request)
        {
            BypassCache = true,
            Source = DnsQuerySource.Udp
        };

        await processor.ExecuteAsync(context, CancellationToken.None);

        await middleware.DidNotReceive()
            .ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>());
        Assert.Equal("UdpRateLimit", context.AnsweredBy);
    }

    [Theory]
    [InlineData(DnsQuerySource.Dot)]
    [InlineData(DnsQuerySource.Doh)]
    public async Task DoesNotLimitDotOrDoh(DnsQuerySource source)
    {
        var limiter = Substitute.For<IUdpQueryRateLimiter>();
        limiter.Record(Arg.Any<IPAddress?>(), Arg.Any<DomainLabels>(), Arg.Any<DomainRecordType>())
            .Returns(UdpRateLimitAction.Drop);
        var middleware = PassthroughMiddleware();
        var processor = Create(limiter, middleware);
        var context = CreateContext(source);

        var response = await processor.ExecuteAsync(context, CancellationToken.None);

        await middleware.Received(1)
            .ProcessAsync(context, Arg.Any<CancellationToken>());
        limiter.DidNotReceive()
            .Record(Arg.Any<IPAddress?>(), Arg.Any<DomainLabels>(), Arg.Any<DomainRecordType>());
        Assert.NotNull(response);
        Assert.Equal(DomainResponseCode.NoError, response!.Flags.ResponseCode);
    }

    [Fact]
    public async Task ValidServerCookieSkipsClassicDnsLimit()
    {
        var limiter = Substitute.For<IUdpQueryRateLimiter>();
        limiter.Record(Arg.Any<IPAddress?>(), Arg.Any<DomainLabels>(), Arg.Any<DomainRecordType>())
            .Returns(UdpRateLimitAction.Drop);
        var middleware = PassthroughMiddleware();
        var factory = new DnsServerCookieFactory(
            new StaticDnsServerCookieSecretSource(Enumerable.Range(1, 32).Select(i => (byte)i).ToArray()),
            TimeProvider.System);
        var processor = Create(limiter, middleware, factory);
        var clientCookie = ImmutableArray.Create<byte>(1, 2, 3, 4, 5, 6, 7, 8);
        var serverCookie = factory.Create(clientCookie.AsSpan(), Client.Address);
        var request = WithOptCookie(
            DomainMessage.CreateRequest("cisco.com", DomainRecordType.TXT),
            clientCookie.AddRange(serverCookie));
        var context = new DomainMessageContext(Client, Server, request) { Source = DnsQuerySource.Udp };

        await processor.ExecuteAsync(context, CancellationToken.None);

        await middleware.Received(1)
            .ProcessAsync(context, Arg.Any<CancellationToken>());
        limiter.DidNotReceive()
            .Record(Arg.Any<IPAddress?>(), Arg.Any<DomainLabels>(), Arg.Any<DomainRecordType>());
        Assert.True(context.CookieConfirmed);
    }

    [Fact]
    public async Task ClientCookieAloneDoesNotSkipLimit()
    {
        var limiter = Substitute.For<IUdpQueryRateLimiter>();
        limiter.Record(Arg.Any<IPAddress?>(), Arg.Any<DomainLabels>(), Arg.Any<DomainRecordType>())
            .Returns(UdpRateLimitAction.Refuse);
        var middleware = PassthroughMiddleware();
        var factory = new DnsServerCookieFactory(
            new StaticDnsServerCookieSecretSource(Enumerable.Range(1, 32).Select(i => (byte)i).ToArray()),
            TimeProvider.System);
        var processor = Create(limiter, middleware, factory);
        var request = WithOptCookie(
            DomainMessage.CreateRequest("cisco.com", DomainRecordType.TXT),
            ImmutableArray.Create<byte>(1, 2, 3, 4, 5, 6, 7, 8));
        var context = new DomainMessageContext(Client, Server, request) { Source = DnsQuerySource.Udp };

        await processor.ExecuteAsync(context, CancellationToken.None);

        await middleware.DidNotReceive()
            .ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>());
        Assert.Equal("UdpRateLimit", context.AnsweredBy);
        Assert.False(context.CookieConfirmed);
    }

    [Fact]
    public async Task SharesWindowAcrossTransports()
    {
        var limiter = CreateSlidingWindowLimiter();
        var middleware = PassthroughMiddleware();
        var processor = Create(limiter, middleware);

        var first = DomainMessage.CreateRequest("cisco.com", DomainRecordType.TXT);
        var firstContext = new DomainMessageContext(Client, Server, first) { Source = DnsQuerySource.Udp };
        await processor.ExecuteAsync(firstContext, CancellationToken.None);
        await middleware.Received(1)
            .ProcessAsync(firstContext, Arg.Any<CancellationToken>());

        middleware.ClearReceivedCalls();
        var second = DomainMessage.CreateRequest("cisco.com", DomainRecordType.TXT);
        var secondContext = new DomainMessageContext(Client, Server, second) { Source = DnsQuerySource.Tcp };
        await processor.ExecuteAsync(secondContext, CancellationToken.None);

        await middleware.DidNotReceive()
            .ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>());
        Assert.Equal("UdpRateLimit", secondContext.AnsweredBy);
    }

    private static IUdpQueryRateLimiter CreateSlidingWindowLimiter()
    {
        var monitor = Substitute.For<IOptionsMonitor<DnsConfiguration>>();
        monitor.CurrentValue.Returns(new DnsConfiguration
        {
            ListenAddresses = ["udp://127.0.0.1:53"],
            UdpRateLimit = new UdpRateLimitConfiguration
            {
                Enabled = true,
                RefuseLimit = 1,
                DropLimit = 3,
                WindowMilliseconds = 1000,
                SegmentsPerWindow = 10
            }
        });
        return new SlidingWindowUdpQueryRateLimiter(monitor);
    }

    private static DomainMessageContextMessageProcessor Create(
        IUdpQueryRateLimiter limiter,
        IDomainMessageMiddleware middleware,
        IDnsServerCookieFactory? cookies = null)
    {
        return new DomainMessageContextMessageProcessor(
            middleware,
            Substitute.For<ILiveQueryEventPublisher>(),
            limiter,
            NullLogger<DomainMessageContextMessageProcessor>.Instance,
            Substitute.For<IDnsMetrics>(),
            cookies);
    }

    private static DomainMessage WithOptCookie(DomainMessage message, ImmutableArray<byte> cookie)
        => message with
        {
            Records = message.Records with
            {
                Additional = ImmutableArray.Create(
                    new DomainResourceRecord(
                        DomainLabels.Empty,
                        DomainRecordType.OPT,
                        (DomainRecordClass)1232,
                        TimeSpan.Zero,
                        new OptionData(ImmutableArray.Create(new EdnsOption(EdnsCookie.OptionCode, cookie)))))
            }
        };

    private static IDomainMessageMiddleware PassthroughMiddleware(DomainMessage? response = null)
    {
        var middleware = Substitute.For<IDomainMessageMiddleware>();
        middleware.Name.Returns("TestHandler");
        middleware.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(call =>
            {
                var context = call.Arg<DomainMessageContext>();
                return new ValueTask<DomainMessage>(
                    response ?? DomainMessage.CreateResponse(
                        context.DomainMessage,
                        DomainResourceRecords.Empty,
                        DomainResponseCode.NoError));
            });
        return middleware;
    }

    private static DomainMessageContext CreateContext(DnsQuerySource source)
    {
        var request = DomainMessage.CreateRequest("cisco.com", DomainRecordType.TXT);
        return new DomainMessageContext(Client, Server, request) { Source = source };
    }
}
