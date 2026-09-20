using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;

using NSubstitute;

namespace Dhcpr.Dns.Core.UnitTests;

public class RecursionAvailableMiddlewareTests
{
    [Fact]
    public async Task StampsRecursionAvailableOnNonNullResult()
    {
        var request = DomainMessage.CreateRequest("example.com");
        var innerResult = DomainMessage.CreateResponse(
            request,
            DomainResourceRecords.Empty,
            DomainResponseCode.NoError);
        Assert.False(innerResult.Flags.RecursionAvailable);

        var inner = Substitute.For<IDomainMessageMiddleware>();
        inner.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(innerResult);

        IDomainMessageMiddleware decorator = new RecursionAvailableMiddleware(inner);
        var result = await decorator.ProcessAsync(
            new DomainMessageContext(null, null, request),
            CancellationToken.None);

        Assert.True(result.Flags.RecursionAvailable);
        Assert.Equal(innerResult.Flags.ResponseCode, result.Flags.ResponseCode);
        Assert.Equal(innerResult.Id, result.Id);
    }
}
