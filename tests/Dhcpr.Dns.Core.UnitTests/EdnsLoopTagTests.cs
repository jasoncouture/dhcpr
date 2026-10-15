using System.Collections.Immutable;
using System.Net;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Protocol.RecordData;

using Microsoft.Extensions.Logging.Abstractions;

using NSubstitute;

namespace Dhcpr.Dns.Core.UnitTests;

public class EdnsLoopTagTests
{
    private static readonly DateTimeOffset FrozenNow = new(2026, 10, 15, 12, 0, 0, TimeSpan.Zero);
    private static readonly byte[] Secret = Enumerable.Range(1, 32).Select(i => (byte)i).ToArray();
    private static readonly IPEndPoint Client = new(IPAddress.Parse("203.0.113.8"), 5353);
    private static readonly IPEndPoint Server = new(IPAddress.Parse("203.0.113.1"), 53);

    [Fact]
    public void EnsureComputesTheCookieOncePerRequest()
    {
        var clock = new CountingTimeProvider(FrozenNow);
        var tag = Tag(clock);
        var context = Context("example.com");

        tag.Ensure(context);
        tag.Ensure(context);

        Assert.Equal(1, clock.Calls);
        Assert.Equal(EdnsLoopTag.TagLength, context.SelfQueryCookie?.Length);
    }

    [Fact]
    public void ShareReusesTheParentCookieForTheSameQuestion()
    {
        var clock = new CountingTimeProvider(FrozenNow);
        var tag = Tag(clock);
        var parent = Context("example.com", DomainRecordType.A);
        var same = DomainMessage.CreateRequest("Example.COM", DomainRecordType.A);
        var other = DomainMessage.CreateRequest("example.com", DomainRecordType.AAAA);

        var first = tag.Share(parent, parent.DomainMessage);
        var second = tag.Share(parent, same);

        Assert.Equal(1, clock.Calls);
        Assert.Equal(first, second);
        Assert.Null(tag.Share(parent, other));
        Assert.Equal(1, clock.Calls);
    }

    [Fact]
    public void IsOursAcceptsTheQuestionWeMarked()
    {
        var tag = Tag();
        var context = Context("Example.COM");
        tag.Ensure(context);
        var wire = DirectedQueryEdns.AddOptRecordWithDoBit(
            context.DomainMessage,
            new EdnsProtocolService(),
            context.SelfQueryCookie);
        var cased = DomainMessage.CreateRequest("example.com") with { Records = wire.Records };

        Assert.True(tag.IsOurs(wire));
        Assert.True(tag.IsOurs(cased));
        Assert.False(tag.IsOurs(DomainMessage.CreateRequest("example.com")));
    }

    [Fact]
    public void IsOursRejectsADifferentTypeAndATamperedTag()
    {
        var tag = Tag();
        var context = Context("example.com");
        tag.Ensure(context);
        var wire = DirectedQueryEdns.AddOptRecordWithDoBit(
            context.DomainMessage,
            new EdnsProtocolService(),
            context.SelfQueryCookie);
        var aaaa = DomainMessage.CreateRequest("example.com", DomainRecordType.AAAA) with
        {
            Records = wire.Records
        };

        Assert.False(tag.IsOurs(aaaa));
        Assert.False(tag.IsOurs(Tamper(wire)));
    }

    [Fact]
    public void IsOursRejectsAnExpiredTag()
    {
        var minted = Tag(new FrozenTimeProvider(FrozenNow));
        var later = Tag(new FrozenTimeProvider(FrozenNow + EdnsLoopTag.Lifetime + TimeSpan.FromSeconds(1)));
        var context = Context("example.com");
        minted.Ensure(context);
        var wire = DirectedQueryEdns.AddOptRecordWithDoBit(
            context.DomainMessage,
            new EdnsProtocolService(),
            context.SelfQueryCookie);

        Assert.True(minted.IsOurs(wire));
        Assert.False(later.IsOurs(wire));
    }

    [Fact]
    public void MissingSecretLeavesTheRequestUnmarked()
    {
        var tag = new EdnsLoopTag(new EmptySecretSource(), new FrozenTimeProvider(FrozenNow));
        var context = Context("example.com");

        tag.Ensure(context);

        Assert.Null(context.SelfQueryCookie);
        Assert.False(tag.IsOurs(context.DomainMessage));
    }

    [Fact]
    public async Task LoopedQueryIsNameErrorBeforeThePipeline()
    {
        var tag = Tag();
        var request = DomainMessage.CreateRequest("netdimensional.top");
        var marked = Context("netdimensional.top");
        tag.Ensure(marked);
        var wire = DirectedQueryEdns.AddOptRecordWithDoBit(
            request,
            new EdnsProtocolService(),
            marked.SelfQueryCookie);
        var middleware = Substitute.For<IDomainMessageMiddleware>();
        var processor = new DomainMessageContextMessageProcessor(
            middleware,
            Substitute.For<ILiveQueryEventPublisher>(),
            Substitute.For<IUdpQueryRateLimiter>(),
            NullLogger<DomainMessageContextMessageProcessor>.Instance,
            Substitute.For<IDnsMetrics>(),
            cookies: null,
            loopTag: tag);
        var inbound = new DomainMessageContext(Client, Server, wire) { Source = DnsQuerySource.Udp };

        var response = await processor.ExecuteAsync(inbound, CancellationToken.None);

        Assert.NotNull(response);
        Assert.Equal(DomainResponseCode.NameError, response!.Flags.ResponseCode);
        Assert.True(response.Flags.Response);
        Assert.Equal(wire.Id, response.Id);
        Assert.Equal("Loop", inbound.AnsweredBy);
        await middleware.DidNotReceive()
            .ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>());
    }

    private static EdnsLoopTag Tag(TimeProvider? time = null)
        => new(new StaticSecretSource(Secret), time ?? new FrozenTimeProvider(FrozenNow));

    private static DomainMessageContext Context(string name, DomainRecordType type = DomainRecordType.A)
        => new(null, null, DomainMessage.CreateRequest(name, type));

    private static DomainMessage Tamper(DomainMessage message)
    {
        var additional = message.Records.Additional;
        var opt = additional.Single(record => record.Type == DomainRecordType.OPT);
        var data = (OptionData)opt.Data;
        var option = data.Options.Single(item => item.Code == EdnsLoopTag.OptionCode);
        var bytes = option.Data.ToArray();
        bytes[^1] ^= 0xff;
        var replaced = new EdnsOption(option.Code, bytes.ToImmutableArray());
        var options = data.Options.Replace(option, replaced);
        var updated = opt with { Data = new OptionData(options) };
        return message with
        {
            Records = message.Records with { Additional = additional.Replace(opt, updated) }
        };
    }

    private sealed class StaticSecretSource(byte[] secret) : IDnsServerCookieSecretSource
    {
        public bool TryGetSecret(out ReadOnlyMemory<byte> value)
        {
            value = secret;
            return true;
        }
    }

    private sealed class EmptySecretSource : IDnsServerCookieSecretSource
    {
        public bool TryGetSecret(out ReadOnlyMemory<byte> secret)
        {
            secret = default;
            return false;
        }
    }

    private sealed class FrozenTimeProvider(DateTimeOffset utc) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => utc.ToUniversalTime();
    }

    private sealed class CountingTimeProvider(DateTimeOffset utc) : TimeProvider
    {
        public int Calls { get; private set; }

        public override DateTimeOffset GetUtcNow()
        {
            Calls++;
            return utc.ToUniversalTime();
        }
    }
}
