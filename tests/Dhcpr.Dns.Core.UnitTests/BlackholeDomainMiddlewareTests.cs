using System.Net;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;

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

    [Fact]
    public async Task OtherNamesPassThrough()
    {
        var request = DomainMessage.CreateRequest("example.com", DomainRecordType.A);
        var response = DomainMessage.CreateResponse(request, responseCode: DomainResponseCode.NoError);
        var inner = Substitute.For<IDomainMessageMiddleware>();
        inner.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(_ => new ValueTask<DomainMessage?>(response));

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
