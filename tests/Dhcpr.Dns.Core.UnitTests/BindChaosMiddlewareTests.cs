using System.Net;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Protocol.RecordData;

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
        Assert.Equal(TimeSpan.Zero, answer.TimeToLive);
        var text = Assert.IsType<TextData>(answer.Data);
        Assert.Equal(expected, text.Text);
        Assert.Equal("bind-chaos", context.AnsweredBy);
        Assert.True(context.DoNotCacheResponse);
        await inner.DidNotReceiveWithAnyArgs()
            .ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>());
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
    [InlineData(DomainRecordClass.HS)]
    [InlineData(DomainRecordClass.CS)]
    [InlineData(DomainRecordClass.Any)]
    [InlineData(DomainRecordClass.None)]
    [InlineData((DomainRecordClass)99)]
    public async Task NonInternetNonChaosIsNotImplemented(DomainRecordClass @class)
    {
        var inner = Substitute.For<IDomainMessageMiddleware>();
        var middleware = new BindChaosMiddleware(inner);
        var request = DomainMessage.CreateRequest("example.com", DomainRecordType.TXT, @class);
        var context = Context(request);

        var result = await middleware.ProcessAsync(context, CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal(DomainResponseCode.NotImplemented, result!.Flags.ResponseCode);
        Assert.False(result.Flags.Authoritative);
        Assert.True(result.Flags.RecursionAvailable);
        Assert.Empty(result.Records.Answers);
        Assert.Equal("query-class", context.AnsweredBy);
        await inner.DidNotReceiveWithAnyArgs()
            .ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>());
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
