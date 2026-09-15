using System.Net;
using System.Net.Sockets;

using Dhcpr.Dns.Core;
using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;

using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

using NSubstitute;

namespace Dhcpr.Dns.Core.UnitTests;

public class DomainMessageRateLimitTests
{
    private static readonly IPEndPoint Client = new(IPAddress.Parse("203.0.113.10"), 53_000);
    private static readonly IPEndPoint Server = new(IPAddress.Parse("192.0.2.1"), 53);

    [Theory]
    [InlineData("udp")]
    [InlineData("tcp")]
    public async Task RefusesClassicDns(string transport)
    {
        var limiter = Substitute.For<IUdpQueryRateLimiter>();
        limiter.Record(Arg.Any<IPAddress?>(), Arg.Any<DomainLabels>(), Arg.Any<DomainRecordType>())
            .Returns(UdpRateLimitAction.Refuse);
        var middleware = PassthroughMiddleware();
        using var processor = Create(limiter, middleware);
        using var hold = CreateMessage(transport, out var message, out var context);

        await processor.ProcessMessageAsync(message, CancellationToken.None);

        await middleware.DidNotReceive()
            .ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>());
        Assert.Equal("UdpRateLimit", context.AnsweredBy);
        if (message is IAwaitableDnsRequest awaitable)
        {
            var response = await awaitable.TaskCompletionSource.Task;
            Assert.NotNull(response);
            Assert.Equal(DomainResponseCode.Refused, response!.Flags.ResponseCode);
        }
    }

    [Theory]
    [InlineData("udp")]
    [InlineData("tcp")]
    public async Task DropsClassicDns(string transport)
    {
        var limiter = Substitute.For<IUdpQueryRateLimiter>();
        limiter.Record(Arg.Any<IPAddress?>(), Arg.Any<DomainLabels>(), Arg.Any<DomainRecordType>())
            .Returns(UdpRateLimitAction.Drop);
        var middleware = PassthroughMiddleware();
        using var processor = Create(limiter, middleware);
        using var hold = CreateMessage(transport, out var message, out var context);

        await processor.ProcessMessageAsync(message, CancellationToken.None);

        await middleware.DidNotReceive()
            .ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>());
        Assert.Equal("UdpRateLimit", context.AnsweredBy);
        Assert.True(context.Cancel);
        if (message is IAwaitableDnsRequest awaitable)
            Assert.Null(await awaitable.TaskCompletionSource.Task);
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
        using var processor = Create(limiter, middleware);
        var context = new DomainMessageContext(Client, Server, request) { IsInternal = true };
        var message = new InternalDnsRequestReceivedMessage(context);

        await processor.ProcessMessageAsync(message, CancellationToken.None);

        await middleware.Received(1)
            .ProcessAsync(context, Arg.Any<CancellationToken>());
        limiter.DidNotReceive()
            .Record(Arg.Any<IPAddress?>(), Arg.Any<DomainLabels>(), Arg.Any<DomainRecordType>());
        var result = await message.TaskCompletionSource.Task;
        Assert.Same(answered, result);
    }

    [Fact]
    public async Task BypassCacheDoesNotSkipLimit()
    {
        var limiter = Substitute.For<IUdpQueryRateLimiter>();
        limiter.Record(Arg.Any<IPAddress?>(), Arg.Any<DomainLabels>(), Arg.Any<DomainRecordType>())
            .Returns(UdpRateLimitAction.Refuse);
        var middleware = PassthroughMiddleware();
        using var processor = Create(limiter, middleware);
        var request = DomainMessage.CreateRequest("cisco.com", DomainRecordType.TXT);
        using var udp = new UdpClient();
        var context = new DomainMessageContext(Client, Server, request)
        {
            BypassCache = true,
            Source = DnsQuerySource.Udp
        };
        var message = new UdpDnsPacketReceivedMessage(context, udp);

        await processor.ProcessMessageAsync(message, CancellationToken.None);

        await middleware.DidNotReceive()
            .ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>());
        Assert.Equal("UdpRateLimit", context.AnsweredBy);
    }

    [Theory]
    [InlineData("dot")]
    [InlineData("doh")]
    public async Task DoesNotLimitDotOrDoh(string transport)
    {
        var limiter = Substitute.For<IUdpQueryRateLimiter>();
        limiter.Record(Arg.Any<IPAddress?>(), Arg.Any<DomainLabels>(), Arg.Any<DomainRecordType>())
            .Returns(UdpRateLimitAction.Drop);
        var middleware = PassthroughMiddleware();
        using var processor = Create(limiter, middleware);
        using var hold = CreateMessage(transport, out var message, out var context);

        await processor.ProcessMessageAsync(message, CancellationToken.None);

        await middleware.Received(1)
            .ProcessAsync(context, Arg.Any<CancellationToken>());
        limiter.DidNotReceive()
            .Record(Arg.Any<IPAddress?>(), Arg.Any<DomainLabels>(), Arg.Any<DomainRecordType>());
        if (message is IAwaitableDnsRequest awaitable)
        {
            var response = await awaitable.TaskCompletionSource.Task;
            Assert.Equal(DomainResponseCode.NoError, response!.Flags.ResponseCode);
        }
    }

    [Fact]
    public async Task SharesWindowAcrossTransports()
    {
        var limiter = CreateSlidingWindowLimiter();
        var middleware = PassthroughMiddleware();
        using var processor = Create(limiter, middleware);
        using var udpClient = new UdpClient();
        using var tcpClient = new TcpClient();
        await using var tcpStream = new MemoryStream();

        var first = DomainMessage.CreateRequest("cisco.com", DomainRecordType.TXT);
        var firstContext = new DomainMessageContext(Client, Server, first) { Source = DnsQuerySource.Udp };
        await processor.ProcessMessageAsync(
            new UdpDnsPacketReceivedMessage(firstContext, udpClient),
            CancellationToken.None);
        await middleware.Received(1)
            .ProcessAsync(firstContext, Arg.Any<CancellationToken>());

        middleware.ClearReceivedCalls();
        var second = DomainMessage.CreateRequest("cisco.com", DomainRecordType.TXT);
        var secondContext = new DomainMessageContext(Client, Server, second) { Source = DnsQuerySource.Tcp };
        await processor.ProcessMessageAsync(
            new TcpDnsPacketReceivedMessage(secondContext, tcpClient, tcpStream),
            CancellationToken.None);

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
        IDomainMessageMiddleware middleware)
    {
        return new DomainMessageContextMessageProcessor(
            [middleware],
            Substitute.For<ILiveQueryEventPublisher>(),
            limiter,
            NullLogger<DomainMessageContextMessageProcessor>.Instance,
            Substitute.For<IDnsMetrics>());
    }

    private static IDomainMessageMiddleware PassthroughMiddleware(DomainMessage? response = null)
    {
        var middleware = Substitute.For<IDomainMessageMiddleware>();
        middleware.Name.Returns("TestHandler");
        middleware.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(call =>
            {
                var context = call.Arg<DomainMessageContext>();
                return new ValueTask<DomainMessage?>(
                    response ?? DomainMessage.CreateResponse(
                        context.DomainMessage,
                        DomainResourceRecords.Empty,
                        DomainResponseCode.NoError));
            });
        return middleware;
    }

    private static IDisposable CreateMessage(
        string transport,
        out DnsPacketReceivedMessage message,
        out DomainMessageContext context)
    {
        var request = DomainMessage.CreateRequest("cisco.com", DomainRecordType.TXT);
        var source = transport switch
        {
            "udp" => DnsQuerySource.Udp,
            "tcp" => DnsQuerySource.Tcp,
            "dot" => DnsQuerySource.Dot,
            "doh" => DnsQuerySource.Doh,
            _ => throw new ArgumentOutOfRangeException(nameof(transport), transport, null)
        };
        context = new DomainMessageContext(Client, Server, request) { Source = source };
        switch (transport)
        {
            case "udp":
            {
                var client = new UdpClient();
                message = new UdpDnsPacketReceivedMessage(context, client);
                return client;
            }
            case "tcp":
            case "dot":
            {
                var client = new TcpClient();
                var stream = new MemoryStream();
                message = new TcpDnsPacketReceivedMessage(context, client, stream);
                return new Combined(client, stream);
            }
            case "doh":
                message = new HttpDnsPacketReceivedMessage(context);
                return Empty;
            default:
                throw new ArgumentOutOfRangeException(nameof(transport), transport, null);
        }
    }

    private static readonly IDisposable Empty = new Combined();

    private sealed class Combined(params IDisposable[] items) : IDisposable
    {
        public void Dispose()
        {
            foreach (var item in items)
                item.Dispose();
        }
    }
}
