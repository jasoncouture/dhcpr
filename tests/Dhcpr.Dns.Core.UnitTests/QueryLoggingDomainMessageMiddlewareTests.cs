using System.Net;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Protocol.RecordData;

using Microsoft.Extensions.Logging.Abstractions;

using NSubstitute;

namespace Dhcpr.Dns.Core.UnitTests;

public class QueryLoggingDomainMessageMiddlewareTests
{
    [Fact]
    public async Task PassesThroughResponseFromInner()
    {
        var request = DomainMessage.CreateRequest("example.com", DomainRecordType.A);
        var response = DomainMessage.CreateResponse(
            request,
            new[]
            {
                new DomainResourceRecord(
                    new DomainLabels("example.com"),
                    DomainRecordType.A,
                    DomainRecordClass.IN,
                    TimeSpan.FromSeconds(60),
                    new IPAddressData(IPAddress.Parse("93.184.216.34")))
            },
            responseCode: DomainResponseCode.NoError);

        var inner = Substitute.For<IDomainMessageMiddleware>();
        inner.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(_ => new ValueTask<DomainMessage?>(response));

        var middleware = new QueryLoggingDomainMessageMiddleware(
            inner,
            NullLogger<QueryLoggingDomainMessageMiddleware>.Instance);

        var context = new DomainMessageContext(
            new IPEndPoint(IPAddress.Parse("203.0.113.10"), 53000),
            new IPEndPoint(IPAddress.Loopback, 53),
            request);

        var result = await middleware.ProcessAsync(context, CancellationToken.None);

        Assert.Same(response, result);
        await inner.Received(1).ProcessAsync(context, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task DoesNotLogInternalRequests()
    {
        var request = DomainMessage.CreateRequest("example.com", DomainRecordType.A);
        var response = DomainMessage.CreateResponse(request, responseCode: DomainResponseCode.NoError);

        var inner = Substitute.For<IDomainMessageMiddleware>();
        inner.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(_ => new ValueTask<DomainMessage?>(response));

        var middleware = new QueryLoggingDomainMessageMiddleware(
            inner,
            NullLogger<QueryLoggingDomainMessageMiddleware>.Instance);

        var internalEndPoint = new IPEndPoint(IPAddress.Any, 53);
        var context = new DomainMessageContext(internalEndPoint, internalEndPoint, request);

        await middleware.ProcessAsync(context, CancellationToken.None);

        await inner.Received(1).ProcessAsync(context, Arg.Any<CancellationToken>());
    }
}
