using System.Net;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;

using NSubstitute;

namespace Dhcpr.Dns.Core.UnitTests;

public class MetricsDomainMessageMiddlewareTests
{
    [Fact]
    public async Task CountsWhenInnerAnswers()
    {
        var request = DomainMessage.CreateRequest("example.com");
        var response = DomainMessage.CreateResponse(request, responseCode: DomainResponseCode.NoError);
        var (middleware, metrics) = CreateMiddleware(response);
        var context = new DomainMessageContext(
            new IPEndPoint(IPAddress.Parse("203.0.113.10"), 53_000),
            new IPEndPoint(IPAddress.Loopback, 53),
            request);

        var result = await middleware.ProcessAsync(context, CancellationToken.None);

        Assert.Same(response, result);
        metrics.Received(1).RecordQuery(context, response);
    }

    [Fact]
    public async Task CountsBlackholeNxDomain()
    {
        var leaf = Substitute.For<IDomainMessageMiddleware>();
        var monitor = Substitute.For<Microsoft.Extensions.Options.IOptionsMonitor<DnsConfiguration>>();
        monitor.CurrentValue.Returns(new DnsConfiguration { BlackholeDomains = ["dhitc.com"] });
        var blackhole = new BlackholeDomainMiddleware(leaf, monitor);
        var metrics = Substitute.For<IDnsMetrics>();
        var middleware = new MetricsDomainMessageMiddleware(blackhole, metrics);

        var context = new DomainMessageContext(
            new IPEndPoint(IPAddress.Loopback, 53000),
            new IPEndPoint(IPAddress.Loopback, 53),
            DomainMessage.CreateRequest("www.dhitc.com", DomainRecordType.A));

        var result = await middleware.ProcessAsync(context, CancellationToken.None);

        Assert.Equal(DomainResponseCode.NameError, result.Flags.ResponseCode);
        metrics.Received(1).RecordQuery(context, result);
        await leaf.DidNotReceiveWithAnyArgs()
            .ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task PassesResponseToRecordQuery()
    {
        var request = DomainMessage.CreateRequest("missing.example");
        var response = DomainMessage.CreateResponse(request, responseCode: DomainResponseCode.NameError);
        var (middleware, metrics) = CreateMiddleware(response);
        var context = new DomainMessageContext(
            new IPEndPoint(IPAddress.Loopback, 53000),
            new IPEndPoint(IPAddress.Loopback, 53),
            request);

        await middleware.ProcessAsync(context, CancellationToken.None);

        metrics.Received(1).RecordQuery(context, response);
    }

    private static (MetricsDomainMessageMiddleware Middleware, IDnsMetrics Metrics) CreateMiddleware(
        DomainMessage response)
    {
        var inner = Substitute.For<IDomainMessageMiddleware>();
        inner.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(_ => new ValueTask<DomainMessage>(response));
        var metrics = Substitute.For<IDnsMetrics>();
        return (new MetricsDomainMessageMiddleware(inner, metrics), metrics);
    }
}
