using System.Net;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;

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

    [Fact]
    public async Task KnownTypePassesThrough()
    {
        var request = DomainMessage.CreateRequest("example.com", DomainRecordType.A);
        var response = DomainMessage.CreateResponse(request, responseCode: DomainResponseCode.NoError);
        var inner = Substitute.For<IDomainMessageMiddleware>();
        inner.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(_ => new ValueTask<DomainMessage?>(response));

        var middleware = new UnsupportedQueryTypeMiddleware(inner);
        var context = new DomainMessageContext(
            new IPEndPoint(IPAddress.Loopback, 53000),
            new IPEndPoint(IPAddress.Loopback, 53),
            request);

        var result = await middleware.ProcessAsync(context, CancellationToken.None);

        Assert.Same(response, result);
        await inner.Received(1).ProcessAsync(context, Arg.Any<CancellationToken>());
    }
}
