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
        var calls = 0;
        var tag = Tag(FrozenNow, () => calls++);
        var context = Context("example.com");

        tag.Ensure(context);
        tag.Ensure(context);

        Assert.Equal(1, calls);
        Assert.Equal(EdnsLoopTag.TagLength, context.SelfQueryCookie?.Length);
    }

    [Fact]
    public void ShareReusesTheParentCookieForTheSameQuestion()
    {
        var calls = 0;
        var tag = Tag(FrozenNow, () => calls++);
        var parent = Context("example.com", DomainRecordType.A);
        var same = DomainMessage.CreateRequest("Example.COM", DomainRecordType.A);
        var other = DomainMessage.CreateRequest("example.com", DomainRecordType.AAAA);

        var first = tag.Share(parent, parent.DomainMessage);
        var second = tag.Share(parent, same);

        Assert.Equal(1, calls);
        Assert.Equal(first, second);
        Assert.Null(tag.Share(parent, other));
        Assert.Equal(1, calls);
    }

    [Fact]
    public void IsOursAcceptsTheQuestionWeMarked()
    {
        IEdnsLoopTag tag = Tag();
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
        IEdnsLoopTag tag = Tag();
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
        IEdnsLoopTag minted = Tag(FrozenNow);
        IEdnsLoopTag later = Tag(FrozenNow + EdnsLoopTag.Lifetime + TimeSpan.FromSeconds(1));
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
        var secrets = Substitute.For<IDnsServerCookieSecretSource>();
        secrets.TryGetSecret(out Arg.Any<ReadOnlyMemory<byte>>()).Returns(false);
        var clock = Substitute.For<TimeProvider>();
        clock.GetUtcNow().Returns(FrozenNow);
        IEdnsLoopTag tag = new EdnsLoopTag(secrets, clock);
        var context = Context("example.com");

        tag.Ensure(context);

        Assert.Null(context.SelfQueryCookie);
        Assert.False(tag.IsOurs(context.DomainMessage));
    }

    [Fact]
    public async Task LoopedQueryIsRefusedBeforeTheInnerMiddleware()
    {
        IEdnsLoopTag tag = Tag();
        var request = DomainMessage.CreateRequest("netdimensional.top");
        var marked = Context("netdimensional.top");
        tag.Ensure(marked);
        var wire = DirectedQueryEdns.AddOptRecordWithDoBit(
            request,
            new EdnsProtocolService(),
            marked.SelfQueryCookie);
        var inner = Substitute.For<IDomainMessageMiddleware>();
        var middleware = new LoopQueryMiddleware(
            inner,
            tag,
            NullLogger<LoopQueryMiddleware>.Instance);
        var inbound = new DomainMessageContext(Client, Server, wire) { Source = DnsQuerySource.Udp };

        var response = await middleware.ProcessAsync(inbound, CancellationToken.None);

        Assert.Equal(DomainResponseCode.Refused, response.Flags.ResponseCode);
        Assert.True(response.Flags.Response);
        Assert.Equal(wire.Id, response.Id);
        Assert.Equal("Loop", inbound.AnsweredBy);
        await inner.DidNotReceive()
            .ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>());
    }

    private static IEdnsLoopTag Tag(DateTimeOffset? now = null, Action? onClock = null)
    {
        var secrets = Substitute.For<IDnsServerCookieSecretSource>();
        secrets.TryGetSecret(out Arg.Any<ReadOnlyMemory<byte>>())
            .Returns(call =>
            {
                call[0] = new ReadOnlyMemory<byte>(Secret);
                return true;
            });
        var clock = Substitute.For<TimeProvider>();
        clock.GetUtcNow().Returns(_ =>
        {
            onClock?.Invoke();
            return now ?? FrozenNow;
        });
        return new EdnsLoopTag(secrets, clock);
    }

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

}
