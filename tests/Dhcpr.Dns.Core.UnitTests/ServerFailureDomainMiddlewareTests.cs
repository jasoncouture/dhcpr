using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;

namespace Dhcpr.Dns.Core.UnitTests;

public class ServerFailureDomainMiddlewareTests
{
    [Fact]
    public async Task UnhandledQueryReturnsServerFailureNotNameError()
    {
        var middleware = new ServerFailureDomainMiddleware();
        var request = DomainMessage.CreateRequest("example.com");
        var context = new DomainMessageContext(null, null, request);

        var result = await middleware.ProcessAsync(context, CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal(DomainResponseCode.ServerFailure, result!.Flags.ResponseCode);
        Assert.Empty(result.Records.Answers);
        Assert.Equal("Server Failure Fallback", context.AnsweredBy);
    }
}
