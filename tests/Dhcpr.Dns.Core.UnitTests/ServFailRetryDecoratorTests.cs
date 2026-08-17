using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Resolvers.Resolvers.Recursive;

using NSubstitute;

namespace Dhcpr.Dns.Core.UnitTests;

public class ServFailRetryDecoratorTests
{
    [Fact]
    public async Task ReturnsFirstNonServFail()
    {
        var inner = Substitute.For<IDomainMessageMiddleware>();
        var request = DomainMessage.CreateRequest("example.com");
        var ok = DomainMessage.CreateResponse(request, DomainResourceRecords.Empty, DomainResponseCode.NoError);
        inner.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(ok);

        IDomainMessageMiddleware decorator = new ServFailRetryDecorator(inner);
        var context = new DomainMessageContext(null, null, request);

        var result = await decorator.ProcessAsync(context, CancellationToken.None);

        Assert.Same(ok, result);
        await inner.Received(1).ProcessAsync(context, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task RetriesServFailUpToMaxAttempts()
    {
        var inner = Substitute.For<IDomainMessageMiddleware>();
        var request = DomainMessage.CreateRequest("example.com");
        var fail = DomainMessage.CreateResponse(request, DomainResourceRecords.Empty,
            DomainResponseCode.ServerFailure);
        inner.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(fail);

        IDomainMessageMiddleware decorator = new ServFailRetryDecorator(inner);
        var context = new DomainMessageContext(null, null, request) { DnssecScope = new DnssecScope() };

        var result = await decorator.ProcessAsync(context, CancellationToken.None);

        Assert.Equal(DomainResponseCode.ServerFailure, result!.Flags.ResponseCode);
        await inner.Received(ServFailRetryDecorator.MaxAttempts)
            .ProcessAsync(context, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task StopsRetryingWhenLaterAttemptSucceeds()
    {
        var inner = Substitute.For<IDomainMessageMiddleware>();
        var request = DomainMessage.CreateRequest("example.com");
        var fail = DomainMessage.CreateResponse(request, DomainResourceRecords.Empty,
            DomainResponseCode.ServerFailure);
        var ok = DomainMessage.CreateResponse(request, DomainResourceRecords.Empty, DomainResponseCode.NoError);
        inner.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(fail, fail, ok);

        IDomainMessageMiddleware decorator = new ServFailRetryDecorator(inner);
        var context = new DomainMessageContext(null, null, request);

        var result = await decorator.ProcessAsync(context, CancellationToken.None);

        Assert.Same(ok, result);
        await inner.Received(3).ProcessAsync(context, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task ResetsDnssecScopeStatusBetweenRetries()
    {
        var inner = Substitute.For<IDomainMessageMiddleware>();
        var request = DomainMessage.CreateRequest("example.com");
        var fail = DomainMessage.CreateResponse(request, DomainResourceRecords.Empty,
            DomainResponseCode.ServerFailure);
        var ok = DomainMessage.CreateResponse(request, DomainResourceRecords.Empty, DomainResponseCode.NoError);
        var scope = new DnssecScope();
        var statuses = new List<DnssecValidationStatus>();

        inner.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(ci =>
            {
                statuses.Add(scope.Status);
                scope.Observe(DnssecValidationStatus.Bogus);
                return fail;
            }, _ =>
            {
                statuses.Add(scope.Status);
                return ok;
            });

        IDomainMessageMiddleware decorator = new ServFailRetryDecorator(inner);
        var context = new DomainMessageContext(null, null, request) { DnssecScope = scope };

        await decorator.ProcessAsync(context, CancellationToken.None);

        Assert.Equal(2, statuses.Count);
        Assert.Equal(DnssecValidationStatus.Unchecked, statuses[0]);
        Assert.Equal(DnssecValidationStatus.Unchecked, statuses[1]);
    }
}
